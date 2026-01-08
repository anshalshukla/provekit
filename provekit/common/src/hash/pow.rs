use {
    digest::{Digest, Output},
    skyscraper::pow::{solve, verify},
    spongefish_pow::PowStrategy,
    std::{marker::PhantomData, ops::Deref},
    zerocopy::transmute,
};

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total = 0;
    for byte in bytes {
        if *byte == 0 {
            total += 8;
        } else {
            total += byte.leading_zeros();
            break;
        }
    }
    total
}

fn meets_pow_target(digest: &[u8; 32], bits: f64) -> bool {
    let required = bits.max(0.0);
    let zeros = leading_zero_bits(digest) as f64;
    zeros >= required
}

fn digest_pow<D: Digest + Default>(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = D::new();
    hasher.update(challenge);
    hasher.update(&nonce.to_be_bytes());
    let result: Output<D> = hasher.finalize();
    let mut out = [0u8; 32];
    let len = result.deref().len().min(32);
    out[..len].copy_from_slice(&result.deref()[..len]);
    out
}

fn solve_digest_pow<D: Digest + Default>(challenge: &[u8; 32], bits: f64) -> Option<u64> {
    for nonce in 0..=u64::MAX {
        let digest = digest_pow::<D>(challenge, nonce);
        if meets_pow_target(&digest, bits) {
            return Some(nonce);
        }
    }
    None
}

/// Generic PoW helper that uses a byte-oriented digest.
#[derive(Clone)]
pub struct DigestPoW<D> {
    challenge: [u8; 32],
    bits:      f64,
    _marker:   PhantomData<D>,
}

impl<D> PowStrategy for DigestPoW<D>
where
    D: Digest + Default + Clone + Send + Sync + 'static,
{
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self {
            challenge,
            bits,
            _marker: PhantomData,
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        let digest = digest_pow::<D>(&self.challenge, nonce);
        meets_pow_target(&digest, self.bits)
    }

    fn solve(&mut self) -> Option<u64> {
        solve_digest_pow::<D>(&self.challenge, self.bits)
    }
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
