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
    sha2::Sha256,
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
pub struct Sha2Permutation {
    state: [FieldElement; 2],
}

impl AsRef<[FieldElement]> for Sha2Permutation {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Sha2Permutation {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Sha2Permutation {
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
        let mut hasher = Sha256::new();
        hasher.update(common::field_to_bytes_le(self.state[0]));
        hasher.update(common::field_to_bytes_le(self.state[1]));
        let digest = hasher.finalize();
        let left = FieldElement::from_le_bytes_mod_order(&digest[..16]);
        let right = FieldElement::from_le_bytes_mod_order(&digest[16..]);
        self.state = [left, right];
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha2CRH;

impl CRHScheme for Sha2CRH {
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
        let mut hasher = Sha256::new();
        for field in input.borrow() {
            hasher.update(common::field_to_bytes_le(*field));
        }
        Ok(FieldElement::from_le_bytes_mod_order(&hasher.finalize()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha2TwoToOne;

impl TwoToOneCRHScheme for Sha2TwoToOne {
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
        let mut hasher = Sha256::new();
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
pub struct Sha2MerkleConfig;

impl Config for Sha2MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = Sha2CRH;
    type TwoToOneHash = Sha2TwoToOne;
}

#[derive(Clone)]
pub struct Sha2HashConfig;

impl HashConfig for Sha2HashConfig {
    const NAME: &'static str = "sha2";
    type Perm = Sha2Permutation;
    type CRH = Sha2CRH;
    type TwoToOne = Sha2TwoToOne;
    type MerkleConfig = Sha2MerkleConfig;
    type Pow = DigestPoW<Sha256>;
}

impl<P> whir::whir::domainsep::DigestDomainSeparator<Sha2MerkleConfig>
    for DomainSeparator<DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl<P> whir::whir::utils::DigestToUnitSerialize<Sha2MerkleConfig>
    for ProverState<DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl<'a, P> whir::whir::utils::DigestToUnitDeserialize<Sha2MerkleConfig>
    for VerifierState<'a, DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}
