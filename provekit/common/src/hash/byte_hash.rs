use {
    crate::FieldElement,
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{PrimeField, Zero},
    digest::Digest,
    rand08::Rng,
    serde::{Deserialize, Serialize},
    spongefish::duplex_sponge::Permutation,
    std::{borrow::Borrow, marker::PhantomData},
    zeroize::Zeroize,
};

/// Helper trait for hash functions that operate on raw bytes and emit 32-byte
/// digests.
pub trait ByteHash: Send + Sync + 'static {
    fn hash_bytes(data: &[u8]) -> [u8; 32];
}

/// Adapter that turns any `digest::Digest` into a [`ByteHash`].
#[derive(Clone, Copy, Debug, Default)]
pub struct DigestByteHash<D>(PhantomData<D>);

impl<D> ByteHash for DigestByteHash<D>
where
    D: Digest + Default + Send + Sync + 'static,
{
    fn hash_bytes(data: &[u8]) -> [u8; 32] {
        let mut hasher = D::new();
        hasher.update(data);
        let result = hasher.finalize();
        let bytes = result.as_ref();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        out
    }
}

pub fn field_to_bytes_le(value: FieldElement) -> [u8; 32] {
    let mut out = [0u8; 32];
    let limbs = value.into_bigint().0;
    for (i, limb) in limbs.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

fn hash_fields<H: ByteHash>(fields: &[FieldElement]) -> [u8; 32] {
    let mut data = Vec::with_capacity(fields.len() * 32);
    for field in fields {
        data.extend_from_slice(&field_to_bytes_le(*field));
    }
    H::hash_bytes(&data)
}

#[derive(Zeroize)]
pub struct ByteHashPermutation<H: ByteHash> {
    state:  [FieldElement; 2],
    marker: PhantomData<H>,
}

impl<H: ByteHash> Clone for ByteHashPermutation<H> {
    fn clone(&self) -> Self {
        Self {
            state:  self.state,
            marker: PhantomData,
        }
    }
}

impl<H: ByteHash> Default for ByteHashPermutation<H> {
    fn default() -> Self {
        Self {
            state:  [FieldElement::zero(), FieldElement::zero()],
            marker: PhantomData,
        }
    }
}

impl<H: ByteHash> AsRef<[FieldElement]> for ByteHashPermutation<H> {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl<H: ByteHash> AsMut<[FieldElement]> for ByteHashPermutation<H> {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl<H: ByteHash> Permutation for ByteHashPermutation<H> {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::from_le_bytes_mod_order(&iv);
        Self {
            state:  [FieldElement::zero(), felt],
            marker: PhantomData,
        }
    }

    fn permute(&mut self) {
        let out = hash_fields::<H>(&self.state);
        let left = FieldElement::from_le_bytes_mod_order(&out[..16]);
        let right = FieldElement::from_le_bytes_mod_order(&out[16..]);
        self.state = [left, right];
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ByteHashCRH<H: ByteHash>(PhantomData<H>);

impl<H: ByteHash> CRHScheme for ByteHashCRH<H> {
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
        let out = hash_fields::<H>(input.borrow());
        Ok(FieldElement::from_le_bytes_mod_order(&out))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ByteHashTwoToOne<H: ByteHash>(PhantomData<H>);

impl<H: ByteHash> TwoToOneCRHScheme for ByteHashTwoToOne<H> {
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
        let out = hash_fields::<H>(&[*l.borrow(), *r.borrow()]);
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
#[serde(bound = "")]
pub struct ByteHashMerkleConfig<H: ByteHash>(PhantomData<H>);

impl<H: ByteHash> Config for ByteHashMerkleConfig<H> {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = ByteHashCRH<H>;
    type TwoToOneHash = ByteHashTwoToOne<H>;
}
