use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
        OptimizationGoal, Result as R1CSResult, SynthesisError,
    },
};
use ark_std::rand::{SeedableRng, rngs::StdRng};

use curg_groth16_research::{
    Circuit, constraint_matrices_to_dense_matrices, prove::prove, setup::setup, verify::verify,
};

#[derive(Clone)]
struct MyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for MyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> R1CSResult<()> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            a *= &b;
            Ok(a)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        Ok(())
    }
}

fn main() {
    type P = Bn254;
    type ScalarField = <P as Pairing>::ScalarField;

    let c = MyCircuit {
        a: Some(ScalarField::from(5)),
        b: Some(ScalarField::from(7)),
    };

    let cs = ConstraintSystem::<ScalarField>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);
    c.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
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
