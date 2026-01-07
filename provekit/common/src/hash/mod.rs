pub mod blake3;
pub(crate) mod common;
pub mod dispatch;
pub mod poseidon2;
pub mod pow;
pub mod sha2;
pub mod sha3;
pub mod skyscraper;
pub use dispatch::dispatch_hash;
use {
    crate::FieldElement,
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::Config,
    },
    serde::{Deserialize, Serialize},
    spongefish::duplex_sponge::Permutation,
    spongefish_pow::PowStrategy,
    std::{
        fmt::{self, Display},
        str::FromStr,
    },
};

/// Trait describing everything the protocol needs from a hash suite.
pub trait HashConfig: Clone + Send + Sync + 'static {
    /// Human readable name (used for logs/debugging).
    const NAME: &'static str;

    /// Permutation used inside the Fiat-Shamir transcripts.
    type Perm: Permutation<U = FieldElement> + Clone + Default + Send + Sync + 'static;

    /// Collision-resistant hash used for leaves of Merkle trees.
    type CRH: CRHScheme<Input = [FieldElement], Output = FieldElement, Parameters = ()>
        + Clone
        + Send
        + Sync
        + Serialize
        + for<'a> Deserialize<'a>;

    /// Two-to-one hash used for Merkle tree internal nodes.
    type TwoToOne: TwoToOneCRHScheme<Input = FieldElement, Output = FieldElement, Parameters = ()>
        + Clone
        + Send
        + Sync
        + Serialize
        + for<'a> Deserialize<'a>;

    /// Merkle tree configuration consumed by WHIR commitments.
    type MerkleConfig: Config<
            Leaf = [FieldElement],
            LeafDigest = FieldElement,
            InnerDigest = FieldElement,
            LeafHash = Self::CRH,
            TwoToOneHash = Self::TwoToOne,
        > + Clone
        + Send
        + Sync
        + Serialize
        + for<'a> Deserialize<'a>;

    /// Proof-of-work strategy bound to the transcript.
    type Pow: PowStrategy + Clone + Send + Sync + 'static;
}

pub trait WhirCompatibleHash: HashConfig {}

impl WhirCompatibleHash for crate::hash::skyscraper::SkyscraperHashConfig {}
impl WhirCompatibleHash for crate::hash::sha2::Sha2HashConfig {}
impl WhirCompatibleHash for crate::hash::sha3::Sha3HashConfig {}
impl WhirCompatibleHash for crate::hash::blake3::Blake3HashConfig {}
impl WhirCompatibleHash for crate::hash::poseidon2::Poseidon2HashConfig {}

/// Hash suites supported by ProveKit at the protocol layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashFunction {
    SkyscraperV2,
    Sha2,
    Sha3,
    Blake3,
    Poseidon2,
}

impl HashFunction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkyscraperV2 => "skyscraper_v2",
            Self::Sha2 => "sha2",
            Self::Sha3 => "sha3",
            Self::Blake3 => "blake3",
            Self::Poseidon2 => "poseidon2",
        }
    }

    pub const fn variants() -> &'static [&'static str] {
        &["skyscraper_v2", "sha2", "sha3", "blake3", "poseidon2"]
    }
}

impl Default for HashFunction {
    fn default() -> Self {
        Self::SkyscraperV2
    }
}

impl Display for HashFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HashFunction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "skyscraper" | "skyscraper_v2" => Ok(Self::SkyscraperV2),
            "sha2" | "sha256" => Ok(Self::Sha2),
            "sha3" | "sha3-256" => Ok(Self::Sha3),
            "blake3" => Ok(Self::Blake3),
            "poseidon" | "poseidon2" => Ok(Self::Poseidon2),
            other => Err(format!(
                "Unknown hash function '{other}'. Supported values: {}",
                Self::variants().join(", ")
            )),
        }
    }
}
