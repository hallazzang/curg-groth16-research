use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
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

// Vitalik QAP example: proves knowledge of x such that x³ + x + 5 = y
#[derive(Clone)]
struct CubicCircuit<F: Field> {
    pub x: Option<F>, // private witness
    pub y: Option<F>, // public input
}

impl<F: Field> ConstraintSynthesizer<F> for CubicCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> R1CSResult<()> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let out = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;

        let x_val = self.x.unwrap_or_default();
        let x_squared = cs.new_witness_variable(|| Ok(x_val * x_val))?;
        let x_cubed = cs.new_witness_variable(|| Ok(x_val * x_val * x_val))?;
        let x_cubed_add_x = cs.new_witness_variable(|| Ok(x_val * x_val * x_val + x_val))?;

        // Constraint 0: x * x = x²
        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + x_squared)?;

        // Constraint 1: x² * x = x³
        cs.enforce_constraint(lc!() + x_squared, lc!() + x, lc!() + x_cubed)?;

        // Constraint 2: (x³ + x) × 1 = x³ + x
        cs.enforce_constraint(
            lc!() + x_cubed + x,
            lc!() + Variable::One,
            lc!() + x_cubed_add_x,
        )?;

        // Constraint 3: (x³ + x + 5) × 1 = y
        cs.enforce_constraint(
            lc!() + x_cubed_add_x + (F::from(5u32), Variable::One),
            lc!() + Variable::One,
            lc!() + out,
        )?;

        Ok(())
    }
}

// cargo run --example vitalik_qap
fn main() {
    type P = Bn254;
    type ScalarField = <P as Pairing>::ScalarField;

    // x = 3, y = x³ + x + 5 = 27 + 3 + 5 = 35
    let x = ScalarField::from(3u32);
    let y = ScalarField::from(35u32);
    let c = CubicCircuit {
        x: Some(x),
        y: Some(y),
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
