use {
    crate::{
        hash::{common, HashConfig},
        FieldElement,
    },
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{PrimeField, Zero},
    blake3::Hasher,
    rand08::Rng,
    serde::{Deserialize, Serialize},
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        duplex_sponge::{DuplexSponge, Permutation},
        DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    spongefish_pow::PowStrategy,
    std::{borrow::Borrow, io::Read},
    zeroize::Zeroize,
};

#[derive(Clone, Default, Zeroize)]
pub struct Blake3Permutation {
    state: [FieldElement; 2],
}

impl AsRef<[FieldElement]> for Blake3Permutation {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Blake3Permutation {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Blake3Permutation {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::from_le_bytes_mod_order(&iv);
        Self {
            state: [FieldElement::zero(), felt],
        }
    }

    fn permute(&mut self) {
        let mut hasher = Hasher::new();
        hasher.update(&common::field_to_bytes_le(self.state[0]));
        hasher.update(&common::field_to_bytes_le(self.state[1]));
        let mut out = [0u8; 32];
        hasher.finalize_xof().read(&mut out).unwrap();
        let left = FieldElement::from_le_bytes_mod_order(&out[..16]);
        let right = FieldElement::from_le_bytes_mod_order(&out[16..]);
        self.state = [left, right];
    }
}

fn blake3_hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out).unwrap();
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3CRH;

impl CRHScheme for Blake3CRH {
    type Input = [FieldElement];
    type Output = FieldElement;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let mut hasher = Hasher::new();
        for field in input.borrow() {
            hasher.update(&common::field_to_bytes_le(*field));
        }
        let mut out = [0u8; 32];
        hasher.finalize_xof().read(&mut out).unwrap();
        Ok(FieldElement::from_le_bytes_mod_order(&out))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3TwoToOne;

impl TwoToOneCRHScheme for Blake3TwoToOne {
    type Input = FieldElement;
    type Output = FieldElement;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        let mut hasher = Hasher::new();
        hasher.update(&common::field_to_bytes_le(*l.borrow()));
        hasher.update(&common::field_to_bytes_le(*r.borrow()));
        let mut out = [0u8; 32];
        hasher.finalize_xof().read(&mut out).unwrap();
        Ok(FieldElement::from_le_bytes_mod_order(&out))
    }

    fn compress<T: Borrow<Self::Output>>(
        p: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        <Self as TwoToOneCRHScheme>::evaluate(p, l, r)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3MerkleConfig;

impl Config for Blake3MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = Blake3CRH;
    type TwoToOneHash = Blake3TwoToOne;
}

#[derive(Clone)]
pub struct Blake3HashConfig;

impl HashConfig for Blake3HashConfig {
    const NAME: &'static str = "blake3";
    type Perm = Blake3Permutation;
    type CRH = Blake3CRH;
    type TwoToOne = Blake3TwoToOne;
    type MerkleConfig = Blake3MerkleConfig;
    type Pow = Blake3PoW;
}

/// Simple PoW that reuses BLAKE3 as the compression function.
#[derive(Clone)]
pub struct Blake3PoW {
    challenge: [u8; 32],
    bits:      f64,
}

fn meets_pow_target(digest: &[u8; 32], bits: f64) -> bool {
    let required = bits.max(0.0);
    let zeros = digest.iter().fold(0u32, |acc, byte| {
        if acc / 8 < required as u32 {
            acc + byte.leading_zeros()
        } else {
            acc
        }
    }) as f64;
    zeros >= required
}

impl PowStrategy for Blake3PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self { challenge, bits }
    }

    fn check(&mut self, nonce: u64) -> bool {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&self.challenge);
        data.extend_from_slice(&nonce.to_be_bytes());
        let digest = blake3_hash_bytes(&data);
        meets_pow_target(&digest, self.bits)
    }

    fn solve(&mut self) -> Option<u64> {
        for nonce in 0..=u64::MAX {
            if self.check(nonce) {
                return Some(nonce);
            }
        }
        None
    }
}

impl<P> whir::whir::domainsep::DigestDomainSeparator<Blake3MerkleConfig>
    for DomainSeparator<DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl<P> whir::whir::utils::DigestToUnitSerialize<Blake3MerkleConfig>
    for ProverState<DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl<'a, P> whir::whir::utils::DigestToUnitDeserialize<Blake3MerkleConfig>
    for VerifierState<'a, DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}
