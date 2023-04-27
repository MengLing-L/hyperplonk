use ark_bls12_381::{Fr, G1Projective};
use fn_timer::fn_timer;
use hyperplonk::prelude::{CustomizedGates, WitnessColumn};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

use super::PlonkImplInner;
use crate::{config::CIRCUIT_CONFIG, mock::MockCircuit};

impl PlonkImplInner {
    #[fn_timer]
    pub fn init_circuit(&self, seed: [u8; 32]) -> MockCircuit<Fr> {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let jf_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
        let circuit = MockCircuit::<Fr>::new(&mut rng, 1 << CIRCUIT_CONFIG.custom_degree, &jf_gate);
        // assert_eq!(circuit.num_wire_types, NUM_WIRE_TYPES);
        circuit
    }

    #[fn_timer]
    pub fn store_w_evals(&self, witnesses: &[WitnessColumn<Fr>]) {
        self.w_0.store(&witnesses[0].0).unwrap();
        self.w_1.store(&witnesses[1].0).unwrap();
        self.w_2.store(&witnesses[2].0).unwrap();
        self.w_3.store(&witnesses[3].0).unwrap();
        self.w_4.store(&witnesses[4].0).unwrap();
    }
}
