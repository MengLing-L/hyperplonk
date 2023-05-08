use std::sync::Arc;

use arithmetic::{build_eq_x_r, fix_variables, DenseMultilinearExtension, VirtualPolynomial};
use ark_bls12_381::Fr;
use ark_ff::{One, PrimeField};
use ark_std::{cfg_into_iter, log2, Zero};
use fn_timer::fn_timer;
// #[cfg(feature = "parallel")]
use hyperplonk::prelude::{CustomizedGates, HyperPlonkErrors};
use rayon::{
    iter::IntoParallelIterator,
    prelude::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator},
};
use subroutines::{
    poly_iop::{structs::IOPProverState, sum_check::prover::extrapolate},
    PolyIOPErrors,
};

use super::PlonkImplInner;
use crate::config::CIRCUIT_CONFIG;

impl PlonkImplInner {
    #[fn_timer]
    pub fn sum_check(
        &self,
        num_vars: usize,
        state: &mut IOPProverState<Fr>,
        challenges: &[Option<Fr>],
    ) -> Vec<Fr> {
        // if state.round >= state.poly.aux_info.num_variables {
        //     return Err(hyperplonk::prelude::HyperPlonkErrors::PolyIOPErrors(PolyIOPErrors::InvalidProver(
        //         "Prover is not active".to_string(),
        //     )));
        // }

        // let fix_argument = start_timer!(|| "fix argument");

        // Step 1:
        // fix argument and evaluate f(x) over x_m = r; where r is the challenge
        // for the current round, and m is the round number, indexed from 1
        //
        // i.e.:
        // at round m <= n, for each mle g(x_1, ... x_n) within the flattened_mle
        // which has already been evaluated to
        //
        //    g(r_1, ..., r_{m-1}, x_m ... x_n)
        //
        // eval g over r_m, and mutate g to g(r_1, ... r_m,, x_{m+1}... x_n)
        let mut flattened_ml_extensions: Vec<DenseMultilinearExtension<Fr>> =
            state.poly.flattened_ml_extensions.par_iter().map(|x| x.as_ref().clone()).collect(); // worker

        // if state.round == 0 {
        //     return Err(hyperplonk::prelude::HyperPlonkErrors::PolyIOPErrors(PolyIOPErrors::InvalidProver(
        //         "first round should be prover first.".to_string(),
        //     )));
        // }

        if state.round != 0 {
            let r = state.challenges[state.round - 1];
            #[cfg(feature = "parallel")]
            flattened_ml_extensions.par_iter_mut().for_each(|mle| *mle = fix_variables(mle, &[r]));
            #[cfg(not(feature = "parallel"))]
            flattened_ml_extensions.iter_mut().for_each(|mle| *mle = fix_variables(mle, &[r]));
        }
        // end_timer!(fix_argument);

        state.round += 1;

        let products_list = state.poly.products.clone();
        let mut products_sum = vec![Fr::zero(); state.poly.aux_info.max_degree + 1];

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)

        products_list.iter().for_each(|(coefficient, products)| {
            let mut sum = cfg_into_iter!(0..1 << (state.poly.aux_info.num_variables - state.round))
                .fold(
                    || {
                        (
                            vec![(Fr::zero(), Fr::zero()); products.len()],
                            vec![Fr::zero(); products.len() + 1],
                        )
                    },
                    |(mut buf, mut acc), b| {
                        buf.iter_mut().zip(products.iter()).for_each(|((eval, step), f)| {
                            let table = &flattened_ml_extensions[*f];
                            *eval = table[b << 1];
                            *step = table[(b << 1) + 1] - table[b << 1];
                        });
                        // evaluate ...0
                        acc[0] += buf.iter().map(|(eval, _)| eval).product::<Fr>();
                        // evaluate ...1, ...11, ...111
                        acc[1..].iter_mut().for_each(|acc| {
                            buf.iter_mut().for_each(|(eval, step)| *eval += step as &_);
                            *acc += buf.iter().map(|(eval, _)| eval).product::<Fr>();
                        });
                        (buf, acc)
                    },
                )
                .map(|(_, partial)| partial)
                .collect::<Vec<Vec<Fr>>>();
            let mut temp = sum
                .into_iter()
                .reduce(|mut sum, partial| {
                    sum.iter_mut().zip(partial.iter()).for_each(|(sum, partial)| *sum += partial);
                    sum
                })
                .unwrap();
            temp.iter_mut().for_each(|sum| *sum *= coefficient);
            let extraploation = cfg_into_iter!(0..state.poly.aux_info.max_degree - products.len())
                .map(|i| {
                    let (points, weights) = &state.extrapolation_aux[products.len() - 1];
                    let at = Fr::from((products.len() + 1 + i) as u64);
                    extrapolate(points, weights, &temp, &at)
                })
                .collect::<Vec<_>>();
            products_sum
                .iter_mut()
                .zip(temp.iter().chain(extraploation.iter()))
                .for_each(|(products_sum, sum)| *products_sum += sum);
            //     .map(|(_, partial)| partial)
            //     .reduce(
            //         || vec![F::zero(); products.len() + 1],
            //         |mut sum, partial| {
            //             sum.iter_mut()
            //                 .zip(partial.iter())
            //                 .for_each(|(sum, partial)| *sum += partial);
            //             sum
            //         },
            //     );
            // sum.iter_mut().for_each(|sum| *sum *= coefficient);
            // let extraploation =
            // cfg_into_iter!(0..self.poly.aux_info.max_degree - products.len())
            //     .map(|i| {
            //         let (points, weights) =
            // &self.extrapolation_aux[products.len() - 1];
            //         let at = F::from((products.len() + 1 + i) as u64);
            //         extrapolate(points, weights, &sum, &at)
            //     })
            //     .collect::<Vec<_>>();
            // products_sum
            //     .iter_mut()
            //     .zip(sum.iter().chain(extraploation.iter()))
            //     .for_each(|(products_sum, sum)| *products_sum += sum);
        });

        // update prover's state to the partial evaluated polynomial
        state.poly.flattened_ml_extensions =
            flattened_ml_extensions.par_iter().map(|x| Arc::new(x.clone())).collect();
        products_sum
    }
}
