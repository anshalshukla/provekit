use {
    crate::{
        hash::{HashConfig, WhirCompatibleHash},
        utils::{serde_hex, sumcheck::SumcheckIOPattern},
        witness::WitnessIOPattern,
        FieldElement,
    },
    serde::{Deserialize, Serialize},
    spongefish::{duplex_sponge::DuplexSponge, DomainSeparator, ProverState, VerifierState},
    std::{
        fmt::{Debug, Formatter},
        sync::Arc,
    },
    tracing::instrument,
    whir::{
        ntt::RSDefault,
        parameters::{
            default_max_pow, DeduplicationStrategy, FoldingFactor, MerkleProofStrategy,
            MultivariateParameters, ProtocolParameters, SoundnessType,
        },
        whir::{domainsep::WhirDomainSeparator, parameters::WhirConfig as GenericWhirConfig},
    },
};

pub type WhirConfig<H> =
    GenericWhirConfig<FieldElement, <H as HashConfig>::MerkleConfig, <H as HashConfig>::Pow>;
pub type IOPattern<H> = DomainSeparator<DuplexSponge<<H as HashConfig>::Perm>, FieldElement>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhirConfigSpec {
    pub num_variables: usize,
    pub batch_size:    usize,
}

impl WhirConfigSpec {
    pub const fn new(num_variables: usize, batch_size: usize) -> Self {
        Self {
            num_variables,
            batch_size,
        }
    }

    pub fn instantiate<H: HashConfig>(&self) -> WhirConfig<H> {
        instantiate_whir_config::<H>(self.num_variables, self.batch_size)
    }
}

pub const MIN_WHIR_NUM_VARIABLES: usize = 12;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSScheme {
    pub m: usize,
    pub w1_size: usize,
    pub m_0: usize,
    pub a_num_terms: usize,
    pub num_challenges: usize,
    pub whir_witness: WhirConfigSpec,
    pub whir_for_hiding_spartan: WhirConfigSpec,
}

impl WhirR1CSScheme {
    #[instrument(skip_all)]
    pub fn create_io_pattern_with_hash<H: WhirCompatibleHash>(&self) -> IOPattern<H>
    where
        DomainSeparator<DuplexSponge<<H as HashConfig>::Perm>, FieldElement>:
            WhirDomainSeparator<FieldElement, <H as HashConfig>::MerkleConfig>,
        for<'a> VerifierState<'a, DuplexSponge<<H as HashConfig>::Perm>, FieldElement>:
            whir::whir::utils::DigestToUnitDeserialize<<H as HashConfig>::MerkleConfig>,
        ProverState<DuplexSponge<<H as HashConfig>::Perm>, FieldElement>:
            whir::whir::utils::DigestToUnitSerialize<<H as HashConfig>::MerkleConfig>,
    {
        let whir_witness = self.whir_witness.instantiate::<H>();
        let whir_for_hiding_spartan = self.whir_for_hiding_spartan.instantiate::<H>();
        let mut io = IOPattern::<H>::new("🌪️");

        if self.num_challenges > 0 {
            // Compute total constraints: OOD + statement
            let num_witnesses = 2;
            let num_ood_constraints = num_witnesses * whir_witness.committment_ood_samples;
            let num_statement_constraints = 6;
            let num_constraints_total = num_ood_constraints + num_statement_constraints;

            io = io
                .commit_statement(&whir_witness) // C1
                .add_logup_challenges(self.num_challenges)
                .commit_statement(&whir_witness) // C2
                .add_rand(self.m_0)
                .commit_statement(&whir_for_hiding_spartan)
                .add_zk_sumcheck_polynomials(self.m_0)
                .add_whir_proof(&whir_for_hiding_spartan)
                .hint("claimed_evaluations_1")
                .hint("claimed_evaluations_2")
                .add_whir_batch_proof(&whir_witness, num_witnesses, num_constraints_total);
        } else {
            io = io
                .commit_statement(&whir_witness)
                .add_rand(self.m_0)
                .commit_statement(&whir_for_hiding_spartan)
                .add_zk_sumcheck_polynomials(self.m_0)
                .add_whir_proof(&whir_for_hiding_spartan)
                .hint("claimed_evaluations")
                .add_whir_proof(&whir_witness);
        }

        io
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSProof {
    #[serde(with = "serde_hex")]
    pub transcript: Vec<u8>,
}

// TODO: Implement Debug for WhirConfig and derive.
impl Debug for WhirR1CSScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhirR1CSScheme")
            .field("m", &self.m)
            .field("w1_size", &self.w1_size)
            .field("m_0", &self.m_0)
            .finish()
    }
}

fn instantiate_whir_config<H: HashConfig>(
    num_variables: usize,
    batch_size: usize,
) -> WhirConfig<H> {
    let nv = num_variables.max(MIN_WHIR_NUM_VARIABLES);
    let mv_params = MultivariateParameters::new(nv);

    let whir_params = ProtocolParameters {
        initial_statement: true,
        security_level: 128,
        pow_bits: default_max_pow(nv, 1),
        folding_factor: FoldingFactor::Constant(4),
        leaf_hash_params: Default::default(),
        two_to_one_params: Default::default(),
        soundness_type: SoundnessType::ConjectureList,
        _pow_parameters: Default::default(),
        starting_log_inv_rate: 1,
        batch_size,
        deduplication_strategy: DeduplicationStrategy::Disabled,
        merkle_proof_strategy: MerkleProofStrategy::Uncompressed,
    };

    let reed_solomon = Arc::new(RSDefault);
    let basefield_reed_solomon = reed_solomon.clone();

    GenericWhirConfig::new(reed_solomon, basefield_reed_solomon, mv_params, whir_params)
}
