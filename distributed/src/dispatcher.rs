use std::{
    cmp::{self, max, min},
    collections::LinkedList,
    convert::TryInto,
    io,
    iter::FromIterator,
    marker::PhantomData,
    mem::size_of,
    net::SocketAddr,
    sync::Arc,
};
use subroutines::poly_iop::structs::IOPProverMessage;
use arithmetic::VPAuxInfo;
use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{scalar_mul::fixed_base::FixedBase, CurveGroup};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, format, rand::RngCore, start_timer};
use fn_timer::fn_timer;
use futures::future::join_all;
use hyperplonk::{
    prelude::{CustomizedGates, HyperPlonkErrors},
    structs::HyperPlonkParams,
};
use stubborn_io::StubbornTcpStream;
use subroutines::{
    pcs::multilinear_kzg::{
        srs::{self, Evaluations, MultilinearProverParam, MultilinearUniversalParams},
        util,
    },
    BatchProof, Commitment, IOPProof, MultilinearVerifierParam, PolynomialCommitmentScheme,
    StructuredReferenceString,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transcript::IOPTranscript;

use crate::{
    config::CIRCUIT_CONFIG,
    structs::HyperPlonkVerifyingKey,
    utils::CastSlice,
    worker::{Method, Status},
};

pub struct HyperPlonk {}

impl HyperPlonk {
    #[fn_timer]
    pub fn universal_setup<R: RngCore>(
        num_vars: usize,
        rng: &mut R,
    ) -> MultilinearUniversalParams<Bls12_381> {
        let total_timer = start_timer!(|| "SRS generation");

        let pp_generation_timer = start_timer!(|| "Prover Param generation");

        let g = G1Projective::rand(rng);
        let h = G2Projective::rand(rng);

        let mut powers_of_g = Vec::new();

        let t: Vec<_> = (0..num_vars).map(|_| Fr::rand(rng)).collect();
        let scalar_bits = Fr::MODULUS_BIT_SIZE as usize;

        let mut eq: LinkedList<DenseMultilinearExtension<Fr>> =
            LinkedList::from_iter(util::eq_extension(&t).into_iter());
        let mut eq_arr = LinkedList::new();
        let mut base = eq.pop_back().unwrap().evaluations;

        for i in (0..num_vars).rev() {
            eq_arr.push_front(srs::remove_dummy_variable(&base, i).unwrap());
            if i != 0 {
                let mul = eq.pop_back().unwrap().evaluations;
                base = base.into_iter().zip(mul.into_iter()).map(|(a, b)| a * b).collect();
            }
        }

        let mut pp_powers = Vec::new();
        let mut total_scalars = 0;
        for i in 0..num_vars {
            let eq = eq_arr.pop_front().unwrap();
            let pp_k_powers = (0..(1 << (num_vars - i))).map(|x| eq[x]);
            pp_powers.extend(pp_k_powers);
            total_scalars += 1 << (num_vars - i);
        }
        let window_size = FixedBase::get_mul_window_size(total_scalars);
        let g_table = FixedBase::get_window_table(scalar_bits, window_size, g);

        let pp_g = G1Projective::normalize_batch(&FixedBase::msm(
            scalar_bits,
            window_size,
            &g_table,
            &pp_powers,
        ));

        let mut start = 0;
        for i in 0..num_vars {
            let size = 1 << (num_vars - i);
            let pp_k_g = Evaluations { evals: pp_g[start..(start + size)].to_vec() };
            // check correctness of pp_k_g
            let t_eval_0 = util::eq_eval(&vec![Fr::zero(); num_vars - i], &t[i..num_vars]).unwrap();
            assert_eq!((g * t_eval_0), pp_k_g.evals[0]);
            powers_of_g.push(pp_k_g);
            start += size;
        }
        let gg = Evaluations { evals: [g.into_affine()].to_vec() };
        powers_of_g.push(gg);

        let pp = MultilinearProverParam {
            num_vars,
            g: g.into_affine(),
            h: h.into_affine(),
            powers_of_g,
        };

        end_timer!(pp_generation_timer);

        let vp_generation_timer = start_timer!(|| "VP generation");
        let h_mask = {
            let window_size = FixedBase::get_mul_window_size(num_vars);
            let h_table = FixedBase::get_window_table(scalar_bits, window_size, h);
            G2Projective::normalize_batch(&FixedBase::msm(scalar_bits, window_size, &h_table, &t))
        };
        end_timer!(vp_generation_timer);
        end_timer!(total_timer);
        MultilinearUniversalParams { prover_param: pp, h_mask }
    }

    #[fn_timer]
    pub async fn key_gen_async(
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        seed: [u8; 32],
        mut srs: MultilinearUniversalParams<Bls12_381>,
        // num_inputs: usize,
    ) -> HyperPlonkVerifyingKey<Bls12_381> {
        let (_, verifier_com_params) = srs.trim(CIRCUIT_CONFIG.custom_nv).unwrap();
        //let (pcs_prover_param, pcs_verifier_param) = PCS::trim(pcs_srs, None, Some(CIRCUIT_CONFIG.custom_nv))?;
        join_all(workers.iter_mut().map(|worker| async move {
            worker.write_u8(Method::KeyGenPrepare as u8).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {}
                _ => panic!(),
            }
        }))
        .await;

        for chunk in srs.prover_param.powers_of_g.cast::<u8>().chunks(1 << 30) {
            join_all(workers.iter_mut().map(|worker| async move {
                loop {
                    worker.write_u8(Method::KeyGenSetCk as u8).await.unwrap();
                    worker.write_u64_le(xxhash_rust::xxh3::xxh3_64(chunk)).await.unwrap();
                    worker.write_u64_le(chunk.len() as u64).await.unwrap();
                    worker.write_all(chunk).await.unwrap();
                    worker.flush().await.unwrap();

                    match worker.read_u8().await.unwrap().try_into().unwrap() {
                        Status::Ok => break,
                        Status::HashMismatch => continue,
                    }
                }
            }))
            .await;
        }

        let c = join_all(workers.iter_mut().enumerate().map(|(i, worker)| async move {
            worker.write_u8(Method::KeyGenCommit as u8).await.unwrap();
            worker.write_all(&seed).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {
                    let mut c_q = vec![G1Projective::zero(); CIRCUIT_CONFIG.selectors[i].len()];
                    worker.read_exact(c_q.cast_mut()).await.unwrap();
                    let mut c_p = vec![G1Projective::zero(); CIRCUIT_CONFIG.permu[i].len()];
                    worker.read_exact(c_p.cast_mut()).await.unwrap();
                    (c_q, c_p)
                }
                _ => panic!(),
            }
        }))
        .await;
        let selector_comms: Vec<Commitment<Bls12_381>> = vec![
            c[0].0[0], c[0].0[1], c[1].0[0], c[1].0[1], c[0].0[2], c[1].0[2], c[0].0[3], c[0].0[4],
            c[1].0[3], c[1].0[4], c[0].0[5], c[1].0[5],
        ]
        .into_iter()
        .map(|c| Commitment(c.into_affine()))
        .collect();
        let permutation_comms: Vec<Commitment<Bls12_381>> =
            vec![c[0].1[0], c[0].1[1], c[1].1[0], c[1].1[1], c[1].1[2]]
                .into_iter()
                .map(|c| Commitment(c.into_affine()))
                .collect();
        HyperPlonkVerifyingKey {
            num_constraints: 1 << CIRCUIT_CONFIG.custom_nv,
            num_pub_input: CIRCUIT_CONFIG.pub_input_len,
            pcs_param: verifier_com_params,
            selector_commitments: selector_comms,
            perm_commitments: permutation_comms,
        }
    }

    pub async fn prove_async(
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        pub_inputs: &[Fr],
        vk: &HyperPlonkVerifyingKey<Bls12_381>,
    ) -> io::Result<()> {
        let start = start_timer!(|| "hyperplonk proving");
        let mut transcript = IOPTranscript::<Fr>::new(b"hyperplonk");

        let wires_poly_comms = Self::commit_wit(workers, &mut transcript).await.unwrap();
        println!("wires_poly_comms:");
        for i in &wires_poly_comms {
            println!("{}", i.0);
        }
        let max_degree = Self::build_f_hat(workers, &mut transcript).await.unwrap();
        println!("{}", max_degree);
        end_timer!(start);
        Ok(())
    }

    #[fn_timer]
    async fn commit_wit(
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        transcript: &mut IOPTranscript<Fr>,
    ) -> Result<Vec<Commitment<Bls12_381>>, HyperPlonkErrors> {
        let start = start_timer!(|| "Commit witness");
        let c = join_all(workers.iter_mut().enumerate().map(|(i, worker)| async move {
            worker.write_u8(Method::WitnessCommit as u8).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {
                    let mut c = vec![G1Projective::zero(); CIRCUIT_CONFIG.permu[i].len()];
                    worker.read_exact(c.cast_mut()).await.unwrap();
                    c
                }
                _ => panic!(),
            }
        }))
        .await;
        let wires_poly_comms: Vec<Commitment<Bls12_381>> =
            vec![c[0][0], c[0][1], c[1][0], c[1][1], c[1][2]]
                .into_iter()
                .map(|c| Commitment(c.into_affine()))
                .collect();
        for w_com in wires_poly_comms.iter() {
            transcript.append_serializable_element(b"w", w_com)?;
        }
        end_timer!(start);
        Ok(wires_poly_comms)
    }

    #[fn_timer]
    async fn build_f_hat(
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        transcript: &mut IOPTranscript<Fr>,
    ) -> Result<usize, HyperPlonkErrors> {
        let start = start_timer!(|| "Build f_hat");
        let r_tmp =
            transcript.get_and_append_challenge_vectors(b"0check r", CIRCUIT_CONFIG.custom_nv)?;
        let r = r_tmp.cast();
        let hash = xxhash_rust::xxh3::xxh3_64(r);

        let degrees = join_all(workers.iter_mut().enumerate().map(|(i, worker)| async move {
            worker.write_u8(Method::BuidFhat as u8).await.unwrap();
            worker.write_u64_le(hash).await.unwrap();
            worker.write_u64_le(r.len() as u64).await.unwrap();
            worker.write_all(r).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {
                    let degree = worker.read_u64_le().await.unwrap();
                    degree
                }
                _ => panic!(),
            }
        }))
        .await;
        let aux_info: VPAuxInfo<Fr> = VPAuxInfo {
            // The max degree is the max degree of any individual variable
            max_degree: max(degrees[0] as usize, degrees[1] as usize),
            num_variables: CIRCUIT_CONFIG.custom_nv,
            phantom: PhantomData::default(),
        };
        transcript.append_serializable_element(b"aux info", &aux_info)?;

        end_timer!(start);
        Ok(max(degrees[0] as usize, degrees[1] as usize))
    }

    #[fn_timer]
    async fn zero_check(
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        transcript: &mut IOPTranscript<Fr>,
        max_degree: usize,
    ) -> Result<IOPProof<Fr>, HyperPlonkErrors> {
        let start = start_timer!(|| "Zero check");
        let mut challenges: Vec<Option<Fr>> = vec![Some(Fr::one()); CIRCUIT_CONFIG.custom_nv - 1];
        for i in 0..CIRCUIT_CONFIG.custom_nv {
            let challenge = Some(transcript.get_and_append_challenge(b"Internal round")?);
            challenges[i] = challenge;
        }
        let product_sums = join_all(workers.iter_mut().enumerate().map(|(i, worker)| async move {
            worker.write_u8(Method::ZeroCheck as u8).await.unwrap();
            worker.write_u64_le(max_degree as u64).await.unwrap();
            worker.write_all(challenges.cast()).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {
                    let mut products_sum =
                        vec![vec![Fr::zero(); max_degree + 1]; CIRCUIT_CONFIG.custom_nv];
                    worker.read_exact(products_sum.cast_mut()).await.unwrap();
                    products_sum
                }
                _ => panic!(),
            }
        }))
        .await;

        // product_sums[0]
        //     .iter_mut()
        //     .zip(product_sums[1])
        //     .for_each(|(products_sum, sum)| ));

        end_timer!(start);
        // Ok(IOPProof {
        //     point: challenges,
        //     proofs: IOPProverMessage {
        //         evaluations: product_sums[0][CIRCUIT_CONFIG.custom_nv - 1],
        //     },
        // })
    }
}
