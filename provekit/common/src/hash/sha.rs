use {
    crate::hash::{
        byte_hash::{
            ByteHashCRH, ByteHashMerkleConfig, ByteHashPermutation, ByteHashTwoToOne,
            DigestByteHash,
        },
        pow::DigestPoW,
    },
    sha2::Sha256,
    sha3::Sha3_256,
};

#[derive(Clone)]
pub struct Sha2HashConfig;

type Sha2ByteHash = DigestByteHash<Sha256>;

crate::hash::impl_hash_suite!(
    Sha2HashConfig,
    "sha2",
    ByteHashPermutation<Sha2ByteHash>,
    ByteHashCRH<Sha2ByteHash>,
    ByteHashTwoToOne<Sha2ByteHash>,
    ByteHashMerkleConfig<Sha2ByteHash>,
    DigestPoW<Sha256>
);

#[derive(Clone)]
pub struct Sha3HashConfig;

type Sha3ByteHash = DigestByteHash<Sha3_256>;

crate::hash::impl_hash_suite!(
    Sha3HashConfig,
    "sha3",
    ByteHashPermutation<Sha3ByteHash>,
    ByteHashCRH<Sha3ByteHash>,
    ByteHashTwoToOne<Sha3ByteHash>,
    ByteHashMerkleConfig<Sha3ByteHash>,
    DigestPoW<Sha3_256>
);
