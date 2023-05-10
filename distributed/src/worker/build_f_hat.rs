use std::sync::Arc;

use arithmetic::{build_eq_x_r, DenseMultilinearExtension, VirtualPolynomial};
use ark_bls12_381::Fr;
use ark_ff::{One, PrimeField};
use ark_std::log2;
use fn_timer::fn_timer;
use hyperplonk::prelude::{CustomizedGates, HyperPlonkErrors};

use super::PlonkImplInner;
use crate::config::CIRCUIT_CONFIG;

impl PlonkImplInner {
    #[fn_timer]
    pub fn build_f(
        &self,
        //gates: &CustomizedGates,
        num_vars: usize,
        selector_mles: &[Arc<DenseMultilinearExtension<Fr>>],
        witness_mles: &[Arc<DenseMultilinearExtension<Fr>>],
        r: &[Fr],
    ) {
        // TODO: check that selector and witness lengths match what is in
        // the gate definition

        let gates = CustomizedGates::jellyfish_turbo_plonk_gate();

        // for selector_mle in selector_mles.iter() {
        //     if selector_mle.num_vars != num_vars {
        //         return Err(HyperPlonkErrors::InvalidParameters(format!(
        //             "selector has different number of vars: {} vs {}",
        //             selector_mle.num_vars, num_vars
        //         )));
        //     }
        // }

        // for witness_mle in witness_mles.iter() {
        //     if witness_mle.num_vars != num_vars {
        //         return Err(HyperPlonkErrors::InvalidParameters(format!(
        //             "selector has different number of vars: {} vs {}",
        //             witness_mle.num_vars, num_vars
        //         )));
        //     }
        // }

        //let mut res = VirtualPolynomial::<Fr>::new(num_vars);
        let this = unsafe { &mut *(self as *const _ as *mut Self) };

        for (coeff, selector, witnesses) in gates.gates.iter() {
            let coeff_fr =
                if *coeff < 0 { -Fr::from(-*coeff as u64) } else { Fr::from(*coeff as u64) };
            let mut mle_list = vec![];
            if let Some(s) = *selector {
                if CIRCUIT_CONFIG.selectors[self.me].contains(&s) {
                    mle_list.push(selector_mles[s].clone())
                }
            }
            for &witness in witnesses.iter() {
                if CIRCUIT_CONFIG.permu[self.me].contains(&witness) {
                    mle_list.push(witness_mles[witness].clone())
                }
            }
            if !mle_list.is_empty() {
                this.f_hat.add_mle_list(mle_list, coeff_fr).unwrap();
            }
        }
        let eq_x_r = build_eq_x_r(r).unwrap();
        this.f_hat.mul_by_mle(eq_x_r, Fr::one()).unwrap();
        print!("{:?}",this.f_hat.aux_info.max_degree);

        // Ok(res)
    }

    #[fn_timer]
    pub fn build_f_hat_exact(&self, r: &[Fr], num_vars: usize) -> u64 {
        let this = unsafe { &mut *(self as *const _ as *mut Self) };
        let selector_oracles: Vec<Arc<DenseMultilinearExtension<Fr>>> = self
            .load_selector()
            .iter()
            .map(|s| {
                let var = log2(s.len()) as usize;
                Arc::new(DenseMultilinearExtension::from_evaluations_slice(var, s))
            })
            .collect();
        let witness_polys: Vec<Arc<DenseMultilinearExtension<Fr>>> = self
            .load_witnes()
            .iter()
            .map(|w| {
                let var = log2(w.len()) as usize;
                Arc::new(DenseMultilinearExtension::from_evaluations_slice(var, w))
            })
            .collect();
        self.build_f(num_vars, &selector_oracles, &witness_polys, r.as_ref());
        print!("{:?}",this.f_hat.aux_info.max_degree);
        this.f_hat.aux_info.max_degree as u64
    }

    #[fn_timer]
    pub fn load_selector(&self) -> Vec<Vec<Fr>> {
        let q_0: Vec<Fr> = self.q_0.load().unwrap();
        let q_1: Vec<Fr> = self.q_1.load().unwrap();
        let q_2: Vec<Fr> = self.q_2.load().unwrap();
        let q_3: Vec<Fr> = self.q_3.load().unwrap();
        let q_4: Vec<Fr> = self.q_4.load().unwrap();
        let q_5: Vec<Fr> = self.q_5.load().unwrap();
        match self.me {
            0 => {
                vec![
                    q_0,
                    q_1,
                    vec![Fr::one(), Fr::one()],
                    vec![Fr::one(), Fr::one()],
                    q_2,
                    vec![Fr::one(), Fr::one()],
                    q_3,
                    q_4,
                    vec![Fr::one(), Fr::one()],
                    vec![Fr::one(), Fr::one()],
                    q_5,
                    vec![Fr::one(), Fr::one()],
                ]
            }
            1 => {
                vec![
                    vec![Fr::one(), Fr::one()],
                    vec![Fr::one(), Fr::one()],
                    q_0,
                    q_1,
                    vec![Fr::one(), Fr::one()],
                    q_2,
                    vec![Fr::one(), Fr::one()],
                    vec![Fr::one(), Fr::one()],
                    q_3,
                    q_4,
                    vec![Fr::one(), Fr::one()],
                    q_5,
                ]
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer]
    pub fn load_witnes(&self) -> Vec<Vec<Fr>> {
        match self.me {
            0 => {
                let w_0: Vec<Fr> = self.w_0.load().unwrap();
                let w_1: Vec<Fr> = self.w_1.load().unwrap();
                vec![
                    w_0,
                    w_1,
                    vec![Fr::one(), Fr::one()],
                    vec![Fr::one(), Fr::one()],
                    vec![Fr::one(), Fr::one()],
                ]
            }
            1 => {
                let w_2: Vec<Fr> = self.w_2.load().unwrap();
                let w_3: Vec<Fr> = self.w_3.load().unwrap();
                let w_4: Vec<Fr> = self.w_4.load().unwrap();
                vec![vec![Fr::one(), Fr::one()], vec![Fr::one(), Fr::one()], w_2, w_3, w_4]
            }
            _ => unreachable!(),
        }
    }
}
