use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
        Result as R1CSResult, SynthesisError, Variable,
    },
};
use ark_std::rand::{SeedableRng, rngs::StdRng};

use curg_groth16_research::{
    Circuit, constraint_matrices_to_dense_matrices, prove::prove, setup::setup, verify::verify,
};


// in >= 10 을 증명하는 서킷
// 제약 전략: in = d + 10 (d >= 0) 을 비트 분해로 강제
#[derive(Clone)]
struct GreaterThanTenCircuit<F: Field> {
    pub in_: Option<F>,
    pub d:   Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for GreaterThanTenCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> R1CSResult<()> {
        // ── 변수 할당 ──────────────────────────────────────────────────────────
        let in_val = self.in_.unwrap_or_default();
        let d_val  = self.d.unwrap_or_default();

        let in_ = cs.new_witness_variable(|| self.in_.ok_or(SynthesisError::AssignmentMissing))?;
        let d   = cs.new_witness_variable(|| self.d.ok_or(SynthesisError::AssignmentMissing))?;

        // d와 in의 비트값을 into_bigint()로 자동 계산
        let bit = |v: F, i: usize| F::from(v.into_bigint().get_bit(i) as u64);
        let d0  = cs.new_witness_variable(|| Ok(bit(d_val,   0)))?;
        let d1  = cs.new_witness_variable(|| Ok(bit(d_val,   1)))?;
        let d2  = cs.new_witness_variable(|| Ok(bit(d_val,   2)))?;
        let d3  = cs.new_witness_variable(|| Ok(bit(d_val,   3)))?;
        let in0 = cs.new_witness_variable(|| Ok(bit(in_val,  0)))?;
        let in1 = cs.new_witness_variable(|| Ok(bit(in_val,  1)))?;
        let in2 = cs.new_witness_variable(|| Ok(bit(in_val,  2)))?;
        let in3 = cs.new_witness_variable(|| Ok(bit(in_val,  3)))?;

        // ── 제약 1: in = d + 10  →  (d + 10) × 1 = in ────────────────────────
        cs.enforce_constraint(
            lc!() + d + (F::from(10u64), Variable::One),
            lc!() + Variable::One,
            lc!() + in_,
        )?;

        // ── 제약 2: d = d0·2⁰ + d1·2¹ + d2·2² + d3·2³ ──────────────────────
        cs.enforce_constraint(
            lc!() + d0 + (F::from(2u64), d1) + (F::from(4u64), d2) + (F::from(8u64), d3),
            lc!() + Variable::One,
            lc!() + d,
        )?;

        // ── 제약 3~6: d_i ∈ {0,1}  →  d_i × (d_i - 1) = 0 ──────────────────
        cs.enforce_constraint(lc!() + d0, lc!() + d0 + (-F::from(1u64), Variable::One), lc!())?;
        cs.enforce_constraint(lc!() + d1, lc!() + d1 + (-F::from(1u64), Variable::One), lc!())?;
        cs.enforce_constraint(lc!() + d2, lc!() + d2 + (-F::from(1u64), Variable::One), lc!())?;
        cs.enforce_constraint(lc!() + d3, lc!() + d3 + (-F::from(1u64), Variable::One), lc!())?;

        // ── 제약 7: in = in0·2⁰ + in1·2¹ + in2·2² + in3·2³ ─────────────────
        cs.enforce_constraint(
            lc!() + in0 + (F::from(2u64), in1) + (F::from(4u64), in2) + (F::from(8u64), in3),
            lc!() + Variable::One,
            lc!() + in_,
        )?;

        // ── 제약 8~11: in_i ∈ {0,1}  →  in_i × (in_i - 1) = 0 ──────────────
        cs.enforce_constraint(lc!() + in0, lc!() + in0 + (-F::from(1u64), Variable::One), lc!())?;
        cs.enforce_constraint(lc!() + in1, lc!() + in1 + (-F::from(1u64), Variable::One), lc!())?;
        cs.enforce_constraint(lc!() + in2, lc!() + in2 + (-F::from(1u64), Variable::One), lc!())?;
        cs.enforce_constraint(lc!() + in3, lc!() + in3 + (-F::from(1u64), Variable::One), lc!())?;

        Ok(())
    }
}

fn main() {
    type P = Bn254;
    type ScalarField = <P as Pairing>::ScalarField;

    // ── 입력 범위 ─────────────────────────────────────────────────────────────
    // 이 서킷은 4비트(0~15) 분해를 사용하므로 아래 범위를 벗어나면 constraint 불만족.
    //
    //   in_  : 10 ~ 15   (4비트 범위 내에서 10 이상이어야 함)
    //   d    :  0 ~  5   (d = in - 10 이므로 in의 범위에 따라 결정됨)
    //
    // 예) in=10 → d=0 / in=13 → d=3 / in=15 → d=5
    // ──────────────────────────────────────────────────────────────────────────
    let c = GreaterThanTenCircuit {
        in_: Some(ScalarField::from(15u64)),
        d:   Some(ScalarField::from(5u64)),
    };


    let cs = ConstraintSystem::<ScalarField>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);
    c.generate_constraints(cs.clone()).unwrap();
    cs.finalize();

    // witness 값들이 모든 R1CS constraint를 만족하는지 검증하는 sanity check.
    // 각 constraint(A·z ∘ B·z = C·z)에 실제 변수 값을 대입해 성립 여부를 확인한다.
    // 잘못된 witness(예: x=3인데 y=25)로 proof를 생성하면 수학적으로 불가능하므로,
    // proof 생성 전에 미리 오류를 잡아낸다.
    assert!(cs.is_satisfied().unwrap());

    let (l, r, o) = constraint_matrices_to_dense_matrices(&cs.to_matrices().unwrap());
    let binding = cs.borrow().unwrap();
    let a = [
        binding.instance_assignment.clone(),
        binding.witness_assignment.clone(),
    ]
    .concat();
    let public_inputs = binding.instance_assignment.clone();
    let private_inputs = binding.witness_assignment.clone();
    println!("public_inputs: {:?}", public_inputs);
    println!("private_inputs: {:?}", private_inputs);
    println!("witness: {:?}", a);

    let circuit: Circuit<P> = Circuit {
        l,
        r,
        o,
        num_public_inputs: cs.num_instance_variables(),
        num_private_inputs: cs.num_witness_variables(),
    };

    let rng = &mut StdRng::seed_from_u64(0);

    let srs = setup::<P>(rng, &circuit);

    let proof = prove::<P>(rng, &circuit, &srs, &a);
    println!("proof: {:?}", &proof);

    println!(
        "verified: {}",
        verify::<P>(&circuit, &srs, &public_inputs, &proof)
    );
}