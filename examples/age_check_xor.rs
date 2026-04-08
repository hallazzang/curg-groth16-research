// Simple XOR Hash 기반 Credential 나이 검증 서킷
//
// H(issuer_id, holder_name, dob_year) — docs/simple_xor_hash.md 이론 구현
//
// Round 1: z1 = IV  XOR issuer_id   (IV 상수 → 제약 0개)
// Round 2: z2 = z1  XOR holder_name (AND 32개)
// Round 3: H  = z2  XOR dob_year    (AND 32개)
//
// 공개: xor_hash, current_year
// 비공개: issuer_id, holder_name, dob_year, diff
//
// 제약 수:
//   비트 분해  :   3  (3필드 × 1)
//   Bool 체크  :  96  (3필드 × 32비트)
//   Round 2 AND:  32
//   Round 3 AND:  32
//   Hash packing:  1
//   나이 검증  :   9  (B:1, C:1, D:7)
//   합계       : 173
//
// 실행: cargo run --example age_check_xor --release

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

// IV = 공개 고정 상수 (0xA5A5A5A5)
const IV: u32 = 0xA5A5A5A5;
const MIN_AGE: u64 = 20;

/// 오프체인 XOR 해시 계산 (서킷과 동일한 연산)
fn xor_hash_offchain(issuer_id: u32, holder_name: u32, dob_year: u32) -> u32 {
    let z1 = IV ^ issuer_id;
    let z2 = z1 ^ holder_name;
    z2 ^ dob_year
}

/// Simple XOR Hash + 나이 검증 서킷
#[derive(Clone)]
struct XorAgeCheckCircuit<F: Field> {
    // 공개 입력
    pub xor_hash:     Option<F>,
    pub current_year: Option<F>,
    // 비공개 증인
    pub issuer_id:    Option<F>,
    pub holder_name:  Option<F>,
    pub dob_year:     Option<F>,
    pub diff:         Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for XorAgeCheckCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> R1CSResult<()> {
        let diff_val = self.diff.unwrap_or_default();
        let bit = |v: F, i: usize| F::from(v.into_bigint().get_bit(i) as u64);

        // ── 공개 입력 ─────────────────────────────────────────────────────────
        let xor_hash_var = cs.new_input_variable(|| {
            self.xor_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let current_year_var = cs.new_input_variable(|| {
            self.current_year.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── 비공개 증인: 3개 필드 (32비트 packed) ────────────────────────────
        let issuer_id_var = cs.new_witness_variable(|| {
            self.issuer_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let holder_name_var = cs.new_witness_variable(|| {
            self.holder_name.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let dob_year_var = cs.new_witness_variable(|| {
            self.dob_year.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── 비트 분해용 필드 값 ───────────────────────────────────────────────
        let f1_val = self.issuer_id.unwrap_or_default();
        let f2_val = self.holder_name.unwrap_or_default();
        let f3_val = self.dob_year.unwrap_or_default();

        // issuer_id 비트 변수 (f1[0..31])
        let f1: Vec<Variable> = (0..32)
            .map(|i| cs.new_witness_variable(|| Ok(bit(f1_val, i))).unwrap())
            .collect();
        // holder_name 비트 변수 (f2[0..31])
        let f2: Vec<Variable> = (0..32)
            .map(|i| cs.new_witness_variable(|| Ok(bit(f2_val, i))).unwrap())
            .collect();
        // dob_year 비트 변수 (f3[0..31])
        let f3: Vec<Variable> = (0..32)
            .map(|i| cs.new_witness_variable(|| Ok(bit(f3_val, i))).unwrap())
            .collect();

        // ── 제약 1~3: 비트 분해 packing ──────────────────────────────────────
        // field = Σ bit_i × 2^i
        for (bits, packed) in [(&f1, issuer_id_var), (&f2, holder_name_var), (&f3, dob_year_var)] {
            let mut lc_a = lc!();
            for (i, &b) in bits.iter().enumerate() {
                lc_a = lc_a + (F::from(1u64 << i), b);
            }
            cs.enforce_constraint(lc_a, lc!() + Variable::One, lc!() + packed)?;
        }

        // ── 제약 4~99: Bool 체크 (3 × 32 = 96개) ────────────────────────────
        // bit_i × (bit_i − 1) = 0
        for bits in [&f1, &f2, &f3] {
            for &bi in bits {
                cs.enforce_constraint(
                    lc!() + bi,
                    lc!() + bi + (-F::one(), Variable::One),
                    lc!(),
                )?;
            }
        }

        // ── IV 비트 (고정 상수) ───────────────────────────────────────────────
        let iv_bits: Vec<bool> = (0..32).map(|i| (IV >> i) & 1 == 1).collect();

        // ── 제약 100~131: Round 2 AND 게이트 ────────────────────────────────
        // m2_i = z1_i × f2_i  (z1_i = IV_i XOR f1_i, 선형식)
        let m2: Vec<Variable> = (0..32)
            .map(|i| {
                let z1_i = if iv_bits[i] {
                    F::one() - bit(f1_val, i)
                } else {
                    bit(f1_val, i)
                };
                cs.new_witness_variable(|| Ok(z1_i * bit(f2_val, i))).unwrap()
            })
            .collect();

        for i in 0..32 {
            // z1_lc: IV_i=1 → (1-f1_i), IV_i=0 → f1_i
            let z1_lc = if iv_bits[i] {
                lc!() + Variable::One + (-F::one(), f1[i])
            } else {
                lc!() + f1[i]
            };
            cs.enforce_constraint(z1_lc, lc!() + f2[i], lc!() + m2[i])?;
        }

        // ── 제약 132~163: Round 3 AND 게이트 ────────────────────────────────
        // m3_i = z2_i × f3_i  (z2_i = z1_i + f2_i - 2·m2_i, 선형식)
        let m3: Vec<Variable> = (0..32)
            .map(|i| {
                let z1_i = if iv_bits[i] {
                    F::one() - bit(f1_val, i)
                } else {
                    bit(f1_val, i)
                };
                let m2_i = z1_i * bit(f2_val, i);
                let z2_i = z1_i + bit(f2_val, i) - F::from(2u64) * m2_i;
                cs.new_witness_variable(|| Ok(z2_i * bit(f3_val, i))).unwrap()
            })
            .collect();

        for i in 0..32 {
            // z2_lc = z1_lc + f2[i] - 2·m2[i]
            let z2_lc = if iv_bits[i] {
                lc!() + Variable::One + (-F::one(), f1[i]) + f2[i] + (-F::from(2u64), m2[i])
            } else {
                lc!() + f1[i] + f2[i] + (-F::from(2u64), m2[i])
            };
            cs.enforce_constraint(z2_lc, lc!() + f3[i], lc!() + m3[i])?;
        }

        // ── 제약 164: 최종 Packing ────────────────────────────────────────────
        // H = Σ h_i × 2^i,  h_i = z2_i + f3_i - 2·m3_i
        {
            let mut lc_h = lc!();
            for i in 0..32 {
                let c  = F::from(1u64 << i);          // 2^i
                let c2 = F::from(2u64) * c;            // 2^(i+1)
                if iv_bits[i] {
                    // z2_i = (1-f1_i) + f2_i - 2·m2_i
                    lc_h = lc_h
                        + (c,   Variable::One)
                        + (-c,  f1[i])
                        + (c,   f2[i])
                        + (-c2, m2[i])
                        + (c,   f3[i])
                        + (-c2, m3[i]);
                } else {
                    // z2_i = f1_i + f2_i - 2·m2_i
                    lc_h = lc_h
                        + (c,   f1[i])
                        + (c,   f2[i])
                        + (-c2, m2[i])
                        + (c,   f3[i])
                        + (-c2, m3[i]);
                }
            }
            cs.enforce_constraint(lc_h, lc!() + Variable::One, lc!() + xor_hash_var)?;
        }

        // ── 나이 검증 ──────────────────────────────────────────────────────────
        let diff_var = cs.new_witness_variable(|| {
            self.diff.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let d: Vec<Variable> = (0..7)
            .map(|i| cs.new_witness_variable(|| Ok(bit(diff_val, i))).unwrap())
            .collect();

        // 제약 B: dob_year + MIN_AGE + diff = current_year
        cs.enforce_constraint(
            lc!() + dob_year_var + (F::from(MIN_AGE), Variable::One) + diff_var,
            lc!() + Variable::One,
            lc!() + current_year_var,
        )?;

        // 제약 C: diff = Σ di × 2^i  (i = 0..6)
        {
            let mut lc_d = lc!();
            for (i, &di) in d.iter().enumerate() {
                lc_d = lc_d + (F::from(1u64 << i), di);
            }
            cs.enforce_constraint(lc_d, lc!() + Variable::One, lc!() + diff_var)?;
        }

        // 제약 D: di × (di − 1) = 0  (i = 0..6)
        for &di in &d {
            cs.enforce_constraint(
                lc!() + di,
                lc!() + di + (-F::one(), Variable::One),
                lc!(),
            )?;
        }

        Ok(())
    }
}

fn main() {
    type P = Bn254;
    type ScalarField = <P as Pairing>::ScalarField;

    let current_year: u64 = 2026;
    let dob_year: u32 = 2007;
    let issuer_id: u32 = 1;

    // "ChoiWonHyeok" → 하위 4바이트를 u32로 인코딩
    let holder_name: u32 = {
        let bytes = b"ChoiWonHyeok";
        let mut v = [0u8; 4];
        v.copy_from_slice(&bytes[..4]);
        u32::from_le_bytes(v)
    };

    // ── 오프체인 XOR 해시 계산 ────────────────────────────────────────────────
    let hash_val = xor_hash_offchain(issuer_id, holder_name, dob_year);

    println!("=== Simple XOR Hash 기반 Credential 나이 검증 ===");
    println!("IV           : 0x{IV:08X}");
    println!("issuer_id    : {issuer_id}");
    println!("holder_name  : 0x{holder_name:08X}  ({holder_name})");
    println!("dob_year     : {dob_year}");
    println!("H(xor_hash)  : 0x{hash_val:08X}  ({hash_val})");
    println!("current_year : {current_year}");
    println!();

    // ── 나이 차이 계산 ────────────────────────────────────────────────────────
    let age  = current_year - dob_year as u64;
    let diff = age - MIN_AGE;
    println!("나이 조건 불만족: {age} < {MIN_AGE}");
    println!("나이: {age}세  diff(age - MIN_AGE)");
    println!();

    // ── 서킷 구성 ─────────────────────────────────────────────────────────────
    let circuit = XorAgeCheckCircuit {
        xor_hash:     Some(ScalarField::from(hash_val as u64)),
        current_year: Some(ScalarField::from(current_year)),
        issuer_id:    Some(ScalarField::from(issuer_id as u64)),
        holder_name:  Some(ScalarField::from(holder_name as u64)),
        dob_year:     Some(ScalarField::from(dob_year as u64)),
        diff:         Some(ScalarField::from(diff)),
    };

    // ── R1CS 검증 ─────────────────────────────────────────────────────────────
    let cs = ConstraintSystem::<ScalarField>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();

    println!("제약 수: {}", cs.num_constraints());
    assert!(cs.is_satisfied().unwrap(), "R1CS 제약 불만족!");
    println!("R1CS 제약 만족 ✓");
    println!();

    // ── Groth16 Setup → Prove → Verify ───────────────────────────────────────
    let (l, r, o) = constraint_matrices_to_dense_matrices(&cs.to_matrices().unwrap());
    let binding = cs.borrow().unwrap();
    let witness = [
        binding.instance_assignment.clone(),
        binding.witness_assignment.clone(),
    ]
    .concat();
    let public_inputs = binding.instance_assignment.clone();
    let private_inputs = binding.witness_assignment.clone();
    println!("public_inputs: {:?}", public_inputs);
    println!("private_inputs: {:?}", private_inputs);

    let groth_circuit: Circuit<P> = Circuit {
        l,
        r,
        o,
        num_public_inputs:  cs.num_instance_variables(),
        num_private_inputs: cs.num_witness_variables(),
    };

    let rng   = &mut StdRng::seed_from_u64(42u64);
    let srs   = setup::<P>(rng, &groth_circuit);
    let proof = prove::<P>(rng, &groth_circuit, &srs, &witness);
    let ok    = verify::<P>(&groth_circuit, &srs, &public_inputs, &proof);

    println!("verified: {ok}");
    assert!(ok, "증명 검증 실패!");
}
