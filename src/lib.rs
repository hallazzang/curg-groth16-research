use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_relations::r1cs::ConstraintMatrices;

pub mod polynomial;
pub mod prove;
pub mod setup;
pub mod verify;

use crate::polynomial::lagrange_interpolate;

#[derive(Clone, Debug, PartialEq)]
pub struct Circuit<E: Pairing> {
    pub l: Vec<Vec<E::ScalarField>>,
    pub r: Vec<Vec<E::ScalarField>>,
    pub o: Vec<Vec<E::ScalarField>>,

    pub num_public_inputs: usize,
    pub num_private_inputs: usize,
}

impl<E: Pairing> Circuit<E> {
    pub fn num_constraints(&self) -> usize {
        assert!(self.l.len() == self.r.len() && self.r.len() == self.o.len());
        self.l.len()
    }

    pub fn num_inputs(&self) -> usize {
        self.num_public_inputs + self.num_private_inputs
    }

    pub fn t(&self) -> DensePolynomial<E::ScalarField> {
        (1..=self.num_constraints())
            .map(|i| {
                DensePolynomial::from_coefficients_slice(&[
                    -E::ScalarField::from(i as u64),
                    E::ScalarField::ONE,
                ])
            })
            .reduce(|a, b| a * b)
            .unwrap()
    }

    fn matrix_to_qap<F: Field>(m: &[Vec<F>]) -> Vec<DensePolynomial<F>> {
        let xs: Vec<F> = (1..=m.len() as u64).map(F::from).collect();
        (0..m[0].len())
            .map(|c| m.iter().map(|r| r[c]).collect())
            .map(|ys: Vec<F>| lagrange_interpolate(&xs, &ys))
            .collect()
    }

    pub fn r1cs_to_qap(
        &self,
    ) -> (
        Vec<DensePolynomial<E::ScalarField>>,
        Vec<DensePolynomial<E::ScalarField>>,
        Vec<DensePolynomial<E::ScalarField>>,
    ) {
        (
            Self::matrix_to_qap(&self.l),
            Self::matrix_to_qap(&self.r),
            Self::matrix_to_qap(&self.o),
        )
    }
}

pub fn constraint_matrices_to_dense_matrices<F: Field>(
    cm: &ConstraintMatrices<F>,
) -> (Vec<Vec<F>>, Vec<Vec<F>>, Vec<Vec<F>>) {
    let mut dense_matrices =
        vec![
            vec![
                vec![F::zero(); cm.num_instance_variables + cm.num_witness_variables];
                cm.num_constraints
            ];
            3
        ];
    for (i, &sparse_matrix) in [&cm.a, &cm.b, &cm.c].iter().enumerate() {
        for (j, row) in sparse_matrix.iter().enumerate() {
            for elem in row {
                dense_matrices[i][j][elem.1] = elem.0;
            }
        }
    }
    (
        dense_matrices[0].clone(),
        dense_matrices[1].clone(),
        dense_matrices[2].clone(),
    )
}
