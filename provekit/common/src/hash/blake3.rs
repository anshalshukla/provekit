use {
    crate::hash::byte_hash::{
        ByteHash, ByteHashCRH, ByteHashMerkleConfig, ByteHashPermutation, ByteHashTwoToOne,
    },
    blake3::Hasher,
    spongefish_pow::blake3::Blake3PoW,
    std::io::Read,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3ByteHash;

impl ByteHash for Blake3ByteHash {
    fn hash_bytes(data: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(data);
        let mut out = [0u8; 32];
        hasher.finalize_xof().read(&mut out).unwrap();
        out
    }
}

#[derive(Clone)]
pub struct Blake3HashConfig;

crate::hash::impl_hash_suite!(
    Blake3HashConfig,
    "blake3",
    ByteHashPermutation<Blake3ByteHash>,
    ByteHashCRH<Blake3ByteHash>,
    ByteHashTwoToOne<Blake3ByteHash>,
    ByteHashMerkleConfig<Blake3ByteHash>,
    Blake3PoW
);
