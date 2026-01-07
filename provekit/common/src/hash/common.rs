use {
    crate::FieldElement,
    ark_bn254::Fr,
    ark_ff::{BigInt, PrimeField},
};

pub(crate) fn field_to_bytes_le(value: FieldElement) -> [u8; 32] {
    let mut out = [0u8; 32];
    let limbs = value.into_bigint().0;
    for (i, limb) in limbs.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

pub(crate) fn to_fr(x: FieldElement) -> Fr {
    Fr::new(BigInt(x.into_bigint().0))
}

pub(crate) fn from_fr(x: Fr) -> FieldElement {
    FieldElement::new(x.into_bigint())
}
