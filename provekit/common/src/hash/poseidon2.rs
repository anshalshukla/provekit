use {
    crate::{hash::pow::DigestPoW, FieldElement},
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{PrimeField, Zero},
    rand08::Rng,
    serde::{Deserialize, Serialize},
    sha2::Sha256,
    spongefish::duplex_sponge::Permutation,
    std::borrow::Borrow,
    zeroize::Zeroize,
};

fn poseidon2_sbox(val: FieldElement) -> FieldElement {
    let mut acc = val;
    for _ in 0..4 {
        acc *= val;
    }
    acc
}

#[derive(Clone, Default, Zeroize)]
pub struct Poseidon2Permutation {
    state: [FieldElement; 3],
}

impl AsRef<[FieldElement]> for Poseidon2Permutation {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Poseidon2Permutation {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Poseidon2Permutation {
    type U = FieldElement;
    const N: usize = 3;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::from_le_bytes_mod_order(&iv);
        Self {
            state: [felt, FieldElement::zero(), FieldElement::zero()],
        }
    }

    fn permute(&mut self) {
        const ROUNDS: usize = 8;
        for round in 0..ROUNDS {
            for (i, elem) in self.state.iter_mut().enumerate() {
                let constant = FieldElement::from((round + i) as u64 + 1);
                *elem = poseidon2_sbox(*elem + constant);
            }
            // Simple linear layer: rotate and add
            let rotated = [
                self.state[0] + self.state[1],
                self.state[1] + self.state[2],
                self.state[2] + self.state[0],
            ];
            self.state = rotated;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poseidon2CRH;

impl CRHScheme for Poseidon2CRH {
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
        let mut perm = Poseidon2Permutation::default();
        let mut state = perm.state;
        for field in input.borrow() {
            state[0] += *field;
            perm.state = state;
            perm.permute();
            state = perm.state;
        }
        Ok(state[0])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poseidon2TwoToOne;

impl TwoToOneCRHScheme for Poseidon2TwoToOne {
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
        let mut perm = Poseidon2Permutation::default();
        perm.state = [*l.borrow(), *r.borrow(), FieldElement::zero()];
        perm.permute();
        Ok(perm.state[0])
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
pub struct Poseidon2MerkleConfig;

impl Config for Poseidon2MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = Poseidon2CRH;
    type TwoToOneHash = Poseidon2TwoToOne;
}

#[derive(Clone)]
pub struct Poseidon2HashConfig;

crate::hash::impl_hash_suite!(
    Poseidon2HashConfig,
    "poseidon2",
    Poseidon2Permutation,
    Poseidon2CRH,
    Poseidon2TwoToOne,
    Poseidon2MerkleConfig,
    DigestPoW<Sha256>
);
