use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use subroutines::{Commitment, MultilinearVerifierParam};

/// The HyperPlonk verifying key, consists of the following:
///   - the hyperplonk instance parameters
///   - the commitments to the preprocessed polynomials output by the indexer
///   - the parameters for polynomial commitment
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct HyperPlonkVerifyingKey<E: Pairing> {
    /// Hyperplonk instance parameters
    pub num_constraints: usize,
    /// number of public input
    // public input is only 1 column and is implicitly the first witness column.
    // this size must not exceed number of constraints.
    pub num_pub_input: usize,
    /// The parameters for PCS commitment
    pub pcs_param: MultilinearVerifierParam<E>,
    /// A commitment to the preprocessed selector polynomials
    pub selector_commitments: Vec<Commitment<E>>,
    /// Permutation oracles' commitments
    pub perm_commitments: Vec<Commitment<E>>,
}
