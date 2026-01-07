// Runtime dispatch for hash-specific code.

/// Dispatch the active hash function to a concrete [`HashConfig`]
/// implementation.
#[macro_export]
macro_rules! dispatch_hash {
    ($hash_fn:expr, | $hash_config:ident | $body:expr) => {
        match $hash_fn {
            $crate::hash::HashFunction::SkyscraperV2 => {
                type $hash_config = $crate::hash::skyscraper::SkyscraperHashConfig;
                $body
            }
            $crate::hash::HashFunction::Sha2 => {
                type $hash_config = $crate::hash::sha2::Sha2HashConfig;
                $body
            }
            $crate::hash::HashFunction::Sha3 => {
                type $hash_config = $crate::hash::sha3::Sha3HashConfig;
                $body
            }
            $crate::hash::HashFunction::Blake3 => {
                type $hash_config = $crate::hash::blake3::Blake3HashConfig;
                $body
            }
            $crate::hash::HashFunction::Poseidon2 => {
                type $hash_config = $crate::hash::poseidon2::Poseidon2HashConfig;
                $body
            }
        }
    };
}

pub use dispatch_hash;
