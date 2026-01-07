mod whir_r1cs;

use {
    crate::whir_r1cs::WhirR1CSVerifier,
    anyhow::Result,
    provekit_common::{hash::dispatch_hash, NoirProof, Verifier},
    tracing::instrument,
};

pub trait Verify {
    fn verify(&mut self, proof: &NoirProof) -> Result<()>;
}

impl Verify for Verifier {
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof) -> Result<()> {
        let scheme = self.whir_for_witness.take().expect("missing WHIR scheme");
        dispatch_hash!(self.hash_function, |H| scheme
            .verify_with_hash::<H>(&proof.whir_r1cs_proof))
    }
}

#[cfg(test)]
mod tests {}
