use ark_bls12_381::{Fr, G1Projective};
use ark_ff::UniformRand;
use fn_timer::fn_timer;
use rand::thread_rng;

use super::PlonkImplInner;

impl PlonkImplInner {
    #[fn_timer]
    pub fn init_and_commit_w(&self) -> Vec<G1Projective> {
        match self.me {
            0 => {
                let w_0 = self.w_0.load().unwrap();
                let w_0_c = self.commit_polynomial(&w_0);
                let w_1 = self.w_1.load().unwrap();
                let w_1_c = self.commit_polynomial(&w_1);
                let w_2 = self.w_2.load().unwrap();
                let w_2_c = self.commit_polynomial(&w_2);
                vec![w_0_c, w_1_c, w_2_c]
            }
            1 => {
                let w_3 = self.w_3.load().unwrap();
                let w_3_c = self.commit_polynomial(&w_3);
                let w_4 = self.w_4.load().unwrap();
                let w_4_c = self.commit_polynomial(&w_4);
                vec![w_3_c, w_4_c]
            }
            _ => unreachable!(),
        }
    }
}
