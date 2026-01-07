use {
    crate::{
        hash::{common, pow::DigestPoW, HashConfig},
        FieldElement,
    },
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{PrimeField, Zero},
    digest::Digest,
    rand08::Rng,
    serde::{Deserialize, Serialize},
    sha3::Sha3_256,
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        duplex_sponge::{DuplexSponge, Permutation},
        DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    std::borrow::Borrow,
    zeroize::Zeroize,
};

#[derive(Clone, Default, Zeroize)]
pub struct Sha3Permutation {
    state: [FieldElement; 2],
}

impl AsRef<[FieldElement]> for Sha3Permutation {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Sha3Permutation {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Sha3Permutation {
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
        let mut hasher = Sha3_256::new();
        hasher.update(common::field_to_bytes_le(self.state[0]));
        hasher.update(common::field_to_bytes_le(self.state[1]));
        let digest = hasher.finalize();
        let left = FieldElement::from_le_bytes_mod_order(&digest[..16]);
        let right = FieldElement::from_le_bytes_mod_order(&digest[16..]);
        self.state = [left, right];
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha3CRH;

impl CRHScheme for Sha3CRH {
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
        let mut hasher = Sha3_256::new();
        for field in input.borrow() {
            hasher.update(common::field_to_bytes_le(*field));
        }
        Ok(FieldElement::from_le_bytes_mod_order(&hasher.finalize()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha3TwoToOne;

impl TwoToOneCRHScheme for Sha3TwoToOne {
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
        let mut hasher = Sha3_256::new();
        hasher.update(common::field_to_bytes_le(*l.borrow()));
        hasher.update(common::field_to_bytes_le(*r.borrow()));
        Ok(FieldElement::from_le_bytes_mod_order(&hasher.finalize()))
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
pub struct Sha3MerkleConfig;

impl Config for Sha3MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = Sha3CRH;
    type TwoToOneHash = Sha3TwoToOne;
}

#[derive(Clone)]
pub struct Sha3HashConfig;

impl HashConfig for Sha3HashConfig {
    const NAME: &'static str = "sha3";
    type Perm = Sha3Permutation;
    type CRH = Sha3CRH;
    type TwoToOne = Sha3TwoToOne;
    type MerkleConfig = Sha3MerkleConfig;
    type Pow = DigestPoW<Sha3_256>;
}

impl<P> whir::whir::domainsep::DigestDomainSeparator<Sha3MerkleConfig>
    for DomainSeparator<DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl<P> whir::whir::utils::DigestToUnitSerialize<Sha3MerkleConfig>
    for ProverState<DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl<'a, P> whir::whir::utils::DigestToUnitDeserialize<Sha3MerkleConfig>
    for VerifierState<'a, DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}
