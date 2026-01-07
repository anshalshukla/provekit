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
    ark_ff::{BigInt, PrimeField},
    rand08::Rng,
    serde::{Deserialize, Serialize},
    skyscraper::pow::{solve, verify},
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        duplex_sponge::{DuplexSponge, Permutation},
        DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    spongefish_pow::PowStrategy,
    std::borrow::Borrow,
    zerocopy::transmute,
    zeroize::Zeroize,
};

fn bigint_from_bytes_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let limbs = bytes
        .chunks_exact(8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .collect::<Vec<_>>();
    BigInt::new(limbs.try_into().unwrap())
}

type State = [FieldElement; 2];

#[derive(Clone, Default, Zeroize)]
pub struct SkyscraperPermutation {
    state: State,
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
        let (l2, r2) = skyscraper::reference::permute(
            common::to_fr(self.state[0]),
            common::to_fr(self.state[1]),
        );
        self.state = [common::from_fr(l2), common::from_fr(r2)];
    }
}

pub type SkyscraperSponge = DuplexSponge<SkyscraperPermutation>;

fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
    let l64 = l.into_bigint().0;
    let r64 = r.into_bigint().0;
    let out = skyscraper::simple::compress(l64, r64);
    FieldElement::new(BigInt(out))
}

/// Skyscraper proof of work strategy used by the protocol.
#[derive(Clone, Copy)]
pub struct SkyscraperPoW {
    challenge: [u64; 4],
    bits:      f64,
}

impl PowStrategy for SkyscraperPoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self {
            challenge: transmute!(challenge),
            bits,
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        verify(self.challenge, self.bits, nonce)
    }

    fn solve(&mut self) -> Option<u64> {
        Some(solve(self.challenge, self.bits))
    }
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

impl HashConfig for SkyscraperHashConfig {
    const NAME: &'static str = "skyscraper_v2";
    type Perm = SkyscraperPermutation;
    type CRH = SkyscraperCRH;
    type TwoToOne = SkyscraperTwoToOne;
    type MerkleConfig = SkyscraperMerkleConfig;
    type Pow = SkyscraperPoW;
}

impl<P> whir::whir::domainsep::DigestDomainSeparator<SkyscraperMerkleConfig>
    for DomainSeparator<DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl<P> whir::whir::utils::DigestToUnitSerialize<SkyscraperMerkleConfig>
    for ProverState<DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl<'a, P> whir::whir::utils::DigestToUnitDeserialize<SkyscraperMerkleConfig>
    for VerifierState<'a, DuplexSponge<P>, FieldElement>
where
    P: Permutation<U = FieldElement> + Clone + Default,
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::SkyscraperPoW,
        spongefish::{
            ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, DefaultHash,
            DomainSeparator,
        },
        spongefish_pow::{PoWChallenge, PoWDomainSeparator},
    };

    const BITS: f64 = 10.0;

    #[test]
    fn test_pow_skyscraper() {
        let iopattern = DomainSeparator::<DefaultHash>::new("the proof of work lottery 🎰")
            .add_bytes(1, "something")
            .challenge_pow("rolling dices");

        let mut prover = iopattern.to_prover_state();
        prover.add_bytes(b"\0").expect("Invalid IOPattern");
        prover.challenge_pow::<SkyscraperPoW>(BITS).unwrap();

        let mut verifier = iopattern.to_verifier_state(prover.narg_string());
        let byte = verifier.next_bytes::<1>().unwrap();
        assert_eq!(&byte, b"\0");
        verifier.challenge_pow::<SkyscraperPoW>(BITS).unwrap();
    }
}
