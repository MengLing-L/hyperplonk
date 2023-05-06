// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

use arithmetic::identity_permutation;
use ark_ff::PrimeField;
use ark_std::{log2, test_rng};
use hyperplonk::prelude::{
    CustomizedGates, HyperPlonkIndex, HyperPlonkParams, SelectorColumn, WitnessColumn,
};
use rand::Rng;

use crate::config::CIRCUIT_CONFIG;

pub struct MockCircuit<F: PrimeField> {
    pub public_inputs: Vec<F>,
    pub witnesses: Vec<WitnessColumn<F>>,
    pub index: HyperPlonkIndex<F>,
}

impl<F: PrimeField> MockCircuit<F> {
    /// Number of variables in a multilinear system
    pub fn num_variables(&self) -> usize {
        self.index.num_variables()
    }

    /// number of selector columns
    pub fn num_selector_columns(&self) -> usize {
        self.index.num_selector_columns()
    }

    /// number of witness columns
    pub fn num_witness_columns(&self) -> usize {
        self.index.num_witness_columns()
    }
}

impl<F: PrimeField> MockCircuit<F> {
    /// Generate a mock plonk circuit for the input constraint size.
    pub fn new<R: Rng>(
        rng: &mut R,
        num_constraints: usize,
        gate: &CustomizedGates,
    ) -> MockCircuit<F> {
        // let mut rng = test_rng();
        let nv = log2(num_constraints);
        let num_selectors = gate.num_selector_columns();
        let num_witnesses = gate.num_witness_columns();
        let log_n_wires = log2(num_witnesses);
        let merged_nv = nv + log_n_wires;

        let mut selectors: Vec<SelectorColumn<F>> = vec![SelectorColumn::default(); num_selectors];
        let mut witnesses: Vec<WitnessColumn<F>> = vec![WitnessColumn::default(); num_witnesses];

        for _cs_counter in 0..num_constraints {
            let mut cur_selectors: Vec<F> =
                (0..(num_selectors - 1)).map(|_| F::rand(rng)).collect();
            let cur_witness: Vec<F> = (0..num_witnesses).map(|_| F::rand(rng)).collect();
            let mut last_selector = F::zero();
            for (index, (coeff, q, wit)) in gate.gates.iter().enumerate() {
                if index != num_selectors - 1 {
                    let mut cur_monomial =
                        if *coeff < 0 { -F::from((-coeff) as u64) } else { F::from(*coeff as u64) };
                    cur_monomial = match q {
                        Some(p) => cur_monomial * cur_selectors[*p],
                        None => cur_monomial,
                    };
                    for wit_index in wit.iter() {
                        cur_monomial *= cur_witness[*wit_index];
                    }
                    last_selector += cur_monomial;
                } else {
                    let mut cur_monomial =
                        if *coeff < 0 { -F::from((-coeff) as u64) } else { F::from(*coeff as u64) };
                    for wit_index in wit.iter() {
                        cur_monomial *= cur_witness[*wit_index];
                    }
                    last_selector /= -cur_monomial;
                }
            }
            cur_selectors.push(last_selector);
            for i in 0..num_selectors {
                selectors[i].append(cur_selectors[i]);
            }
            for i in 0..num_witnesses {
                witnesses[i].append(cur_witness[i]);
            }
        }
        //let pub_input_len = ark_std::cmp::min(4, num_constraints);
        let pub_input_len = CIRCUIT_CONFIG.pub_input_len;
        let public_inputs = witnesses[0].0[0..pub_input_len].to_vec();

        let params = HyperPlonkParams {
            num_constraints,
            num_pub_input: public_inputs.len(),
            gate_func: gate.clone(),
        };

        let permutation = identity_permutation(merged_nv as usize, 1);
        let index = HyperPlonkIndex { params, permutation, selectors };

        Self { public_inputs, witnesses, index }
    }

    pub fn is_satisfied(&self) -> bool {
        for current_row in 0..self.num_variables() {
            let mut cur = F::zero();
            for (coeff, q, wit) in self.index.params.gate_func.gates.iter() {
                let mut cur_monomial =
                    if *coeff < 0 { -F::from((-coeff) as u64) } else { F::from(*coeff as u64) };
                cur_monomial = match q {
                    Some(p) => cur_monomial * self.index.selectors[*p].0[current_row],
                    None => cur_monomial,
                };
                for wit_index in wit.iter() {
                    cur_monomial *= self.witnesses[*wit_index].0[current_row];
                }
                cur += cur_monomial;
            }
            if !cur.is_zero() {
                return false;
            }
        }

        true
    }
}
