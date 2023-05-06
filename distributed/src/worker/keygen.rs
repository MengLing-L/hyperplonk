use std::sync::Arc;

use ark_bls12_381::{Fr, G1Projective};
use fn_timer::fn_timer;
use hyperplonk::prelude::{CustomizedGates, SelectorColumn, WitnessColumn};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

use super::PlonkImplInner;
use crate::{
    config::{CIRCUIT_CONFIG, NUM_WIRE_TYPES},
    mock::MockCircuit,
};

impl PlonkImplInner {
    #[fn_timer]
    pub fn init_circuit(&self, seed: [u8; 32]) -> MockCircuit<Fr> {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let jf_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
        let circuit = MockCircuit::<Fr>::new(&mut rng, 1 << CIRCUIT_CONFIG.custom_nv, &jf_gate);
        // assert_eq!(circuit.num_wire_types, NUM_WIRE_TYPES);
        circuit
    }

    #[fn_timer]
    pub fn store_w_evals(&self, witnesses: Vec<WitnessColumn<Fr>>) {
        self.w_0.store(&witnesses[0].0).unwrap();
        self.w_1.store(&witnesses[1].0).unwrap();
        self.w_2.store(&witnesses[2].0).unwrap();
        self.w_3.store(&witnesses[3].0).unwrap();
        self.w_4.store(&witnesses[4].0).unwrap();
    }

    #[fn_timer]
    pub fn init_and_commit_selectors(
        &self,
        selector: Vec<SelectorColumn<Fr>>,
    ) -> Vec<G1Projective> {
        let me = self.me;

        let selectors = CIRCUIT_CONFIG.selectors[me]
            .par_iter()
            .map(|&var| selector[var].0.to_vec())
            .collect::<Vec<_>>();
        let q_0_c = self.commit_polynomial(&selectors[0]);
        self.q_0.store(&selectors[0]).unwrap();
        let q_1_c = self.commit_polynomial(&selectors[1]);
        self.q_1.store(&selectors[1]).unwrap();
        let q_2_c = self.commit_polynomial(&selectors[2]);
        self.q_2.store(&selectors[2]).unwrap();
        let q_3_c = self.commit_polynomial(&selectors[3]);
        self.q_3.store(&selectors[3]).unwrap();
        let q_4_c = self.commit_polynomial(&selectors[4]);
        self.q_4.store(&selectors[4]).unwrap();
        let q_5_c = self.commit_polynomial(&selectors[5]);
        self.q_5.store(&selectors[5]).unwrap();
        vec![q_0_c, q_1_c, q_2_c, q_3_c, q_4_c, q_5_c]
    }

    #[fn_timer]
    pub fn init_and_commit_permu(&self, permu: Vec<Fr>) -> Vec<G1Projective> {
        let chunk_size = 1 << CIRCUIT_CONFIG.custom_nv;
        let mut permuations = vec![];
        for i in 0..NUM_WIRE_TYPES {
            permuations.push(permu[i * chunk_size..(i + 1) * chunk_size].to_vec());
        }

        match self.me {
            0 => {
                self.p_0.store(&permuations[0]);
                let p_0_c = self.commit_polynomial(&permuations[0]);
                self.p_1.store(&permuations[1]);
                let p_1_c = self.commit_polynomial(&permuations[1]);
                self.p_2.store(&permuations[2]);
                let p_2_c = self.commit_polynomial(&permuations[2]);
                vec![p_0_c, p_1_c, p_2_c]
            }
            1 => {
                self.p_3.store(&permuations[3]);
                let p_3_c = self.commit_polynomial(&permuations[3]);
                self.p_4.store(&permuations[4]);
                let p_4_c = self.commit_polynomial(&permuations[4]);
                vec![p_3_c, p_4_c]
            }
            _ => unreachable!(),
        }
    }
}
