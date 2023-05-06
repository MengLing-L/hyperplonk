use ark_bls12_381::{Fr};
use fn_timer::fn_timer;

use crate::config::CIRCUIT_CONFIG;

use super::PlonkImplInner;

impl PlonkImplInner {
    #[fn_timer]
    pub fn build_f_hat_exact(
        &self,
        r: &[Fr],
        num_vars: usize,
    ) -> usize {
        let mut q_0:Vec<Fr> = self.q_0.load().unwrap();
        let mut q_1:Vec<Fr> = self.q_1.load().unwrap();
        let mut q_2:Vec<Fr> = self.q_2.load().unwrap();
        let mut q_3:Vec<Fr> = self.q_3.load().unwrap();
        let mut q_4:Vec<Fr> = self.q_4.load().unwrap();
        let mut q_5:Vec<Fr> = self.q_5.load().unwrap();
        match self.me {
            0 => {

                0
            },
            1 => 1,
            _ => unreachable!(),
        }
    }
}
