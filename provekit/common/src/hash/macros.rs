macro_rules! impl_whir_digest_helpers {
    ($merkle_config:ty) => {
        impl<P> whir::whir::domainsep::DigestDomainSeparator<$merkle_config>
            for spongefish::DomainSeparator<
                spongefish::duplex_sponge::DuplexSponge<P>,
                crate::FieldElement,
            >
        where
            P: spongefish::duplex_sponge::Permutation<U = crate::FieldElement> + Clone + Default,
        {
            fn add_digest(self, label: &str) -> Self {
                <Self as spongefish::codecs::arkworks_algebra::FieldDomainSeparator<
                    crate::FieldElement,
                >>::add_scalars(self, 1, label)
            }
        }

        impl<P> whir::whir::utils::DigestToUnitSerialize<$merkle_config>
            for spongefish::ProverState<
                spongefish::duplex_sponge::DuplexSponge<P>,
                crate::FieldElement,
            >
        where
            P: spongefish::duplex_sponge::Permutation<U = crate::FieldElement> + Clone + Default,
        {
            fn add_digest(&mut self, digest: crate::FieldElement) -> spongefish::ProofResult<()> {
                <Self as spongefish::codecs::arkworks_algebra::FieldToUnitSerialize<
                    crate::FieldElement,
                >>::add_scalars(self, &[digest])
            }
        }

        impl<'a, P> whir::whir::utils::DigestToUnitDeserialize<$merkle_config>
            for spongefish::VerifierState<
                'a,
                spongefish::duplex_sponge::DuplexSponge<P>,
                crate::FieldElement,
            >
        where
            P: spongefish::duplex_sponge::Permutation<U = crate::FieldElement> + Clone + Default,
        {
            fn read_digest(&mut self) -> spongefish::ProofResult<crate::FieldElement> {
                let [r] = <Self as spongefish::codecs::arkworks_algebra::FieldToUnitDeserialize<
                    crate::FieldElement,
                >>::next_scalars(self)?;
                Ok(r)
            }
        }
    };
}

macro_rules! impl_hash_suite {
    ($config:ty, $name:expr, $perm:ty, $crh:ty, $two_to_one:ty, $merkle:ty, $pow:ty) => {
        impl crate::hash::HashConfig for $config {
            const NAME: &'static str = $name;
            type Perm = $perm;
            type CRH = $crh;
            type TwoToOne = $two_to_one;
            type MerkleConfig = $merkle;
            type Pow = $pow;
        }

        crate::hash::impl_whir_digest_helpers!($merkle);
    };
}

pub(crate) use {impl_hash_suite, impl_whir_digest_helpers};
