use {
    crate::{hash::pow::SkyscraperPoW, FieldElement},
    ark_bn254::Fr,
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{BigInt, PrimeField},
    rand08::Rng,
    serde::{Deserialize, Serialize},
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    std::borrow::Borrow,
    zeroize::Zeroize,
};

fn bigint_from_bytes_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let limbs = bytes
        .chunks_exact(8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .collect::<Vec<_>>();
    BigInt::new(limbs.try_into().unwrap())
}

fn to_fr(x: FieldElement) -> Fr {
    Fr::new(BigInt(x.into_bigint().0))
}

fn from_fr(x: Fr) -> FieldElement {
    FieldElement::new(x.into_bigint())
}

#[derive(Clone, Default, Zeroize)]
pub struct SkyscraperPermutation {
    state: [FieldElement; 2],
}

impl AsRef<[FieldElement]> for SkyscraperPermutation {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for SkyscraperPermutation {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for SkyscraperPermutation {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::new(bigint_from_bytes_le(&iv));
        Self {
            state: [0.into(), felt],
        }
    }

    fn permute(&mut self) {
        let (l2, r2) = skyscraper::reference::permute(to_fr(self.state[0]), to_fr(self.state[1]));
        self.state = [from_fr(l2), from_fr(r2)];
    }
}

pub type SkyscraperSponge = DuplexSponge<SkyscraperPermutation>;

fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
    let l64 = l.into_bigint().0;
    let r64 = r.into_bigint().0;
    let out = skyscraper::simple::compress(l64, r64);
    FieldElement::new(BigInt(out))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkyscraperCRH;

impl CRHScheme for SkyscraperCRH {
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
        input
            .borrow()
            .iter()
            .copied()
            .reduce(compress)
            .ok_or(Error::IncorrectInputLength(0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkyscraperTwoToOne;

impl TwoToOneCRHScheme for SkyscraperTwoToOne {
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
        Ok(compress(*l.borrow(), *r.borrow()))
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
pub struct SkyscraperMerkleConfig;

impl Config for SkyscraperMerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = SkyscraperCRH;
    type TwoToOneHash = SkyscraperTwoToOne;
}

#[derive(Clone)]
pub struct SkyscraperHashConfig;

crate::hash::impl_hash_suite!(
    SkyscraperHashConfig,
    "skyscraper_v2",
    SkyscraperPermutation,
    SkyscraperCRH,
    SkyscraperTwoToOne,
    SkyscraperMerkleConfig,
    SkyscraperPoW
);
