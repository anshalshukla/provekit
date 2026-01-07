use {
    crate::{r1cs::R1CSSolver, whir_r1cs::WhirR1CSProver},
    acir::native_types::WitnessMap,
    anyhow::{Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_abi::InputMap,
    provekit_common::{
        hash::{dispatch_hash, HashConfig, WhirCompatibleHash},
        FieldElement, NoirElement, NoirProof, Prover, WhirR1CSScheme,
    },
    spongefish::{duplex_sponge::DuplexSponge, DomainSeparator, ProverState, VerifierState},
    std::path::Path,
    tracing::instrument,
};

mod r1cs;
mod whir_r1cs;
mod witness;

pub trait Prove {
    fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>>;

    fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;
}

impl Prove for Prover {
    #[instrument(skip_all)]
    fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>> {
        let solver = Bn254BlackBoxSolver::default();
        let mut output_buffer = Vec::new();
        let mut foreign_call_executor = DefaultForeignCallBuilder {
            output:       &mut output_buffer,
            enable_mocks: false,
            resolver_url: None,
            root_path:    None,
            package_name: None,
        }
        .build();

        let initial_witness = self.witness_generator.abi().encode(&input_map, None)?;

        let mut witness_stack = nargo::ops::execute_program(
            &self.program,
            initial_witness,
            &solver,
            &mut foreign_call_executor,
        )?;

        Ok(witness_stack
            .pop()
            .context("Missing witness results")?
            .witness)
    }

    #[instrument(skip_all)]
    fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        dispatch_hash!(self.hash_function, |H| prove_with_hash::<H>(
            self,
            prover_toml
        ))
    }
}

fn prove_with_hash<H: WhirCompatibleHash>(
    mut prover: Prover,
    prover_toml: impl AsRef<Path>,
) -> Result<NoirProof>
where
    DomainSeparator<DuplexSponge<<H as HashConfig>::Perm>, FieldElement>:
        whir::whir::domainsep::WhirDomainSeparator<FieldElement, <H as HashConfig>::MerkleConfig>,
    for<'a> VerifierState<'a, DuplexSponge<<H as HashConfig>::Perm>, FieldElement>:
        whir::whir::utils::DigestToUnitDeserialize<<H as HashConfig>::MerkleConfig>,
    ProverState<DuplexSponge<<H as HashConfig>::Perm>, FieldElement>:
        whir::whir::utils::DigestToUnitSerialize<<H as HashConfig>::MerkleConfig>,
{
    let (input_map, _expected_return) =
        read_inputs_from_file(prover_toml.as_ref(), prover.witness_generator.abi())?;

    let acir_witness_idx_to_value_map = prover.generate_witness(input_map)?;

    let io = prover.whir_for_witness.create_io_pattern_with_hash::<H>();
    let mut merlin = io.to_prover_state();

    let mut witness: Vec<Option<FieldElement>> = vec![None; prover.r1cs.num_witnesses()];

    prover.r1cs.solve_witness_vec::<H>(
        &mut witness,
        prover.split_witness_builders.w1_layers,
        &acir_witness_idx_to_value_map,
        &mut merlin,
    );

    let w1 = witness[..prover.whir_for_witness.w1_size]
        .iter()
        .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w1 are missing")))
        .collect::<Result<Vec<_>>>()?;

    let commitment_1 = <WhirR1CSScheme as WhirR1CSProver<H>>::commit(
        &prover.whir_for_witness,
        &mut merlin,
        &prover.r1cs,
        w1,
        true,
    )
    .context("While committing to w1")?;

    let commitments = if prover.whir_for_witness.num_challenges > 0 {
        prover.r1cs.solve_witness_vec::<H>(
            &mut witness,
            prover.split_witness_builders.w2_layers,
            &acir_witness_idx_to_value_map,
            &mut merlin,
        );

        let w2 = witness[prover.whir_for_witness.w1_size..]
            .iter()
            .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w2 are missing")))
            .collect::<Result<Vec<_>>>()?;

        let commitment_2 = <WhirR1CSScheme as WhirR1CSProver<H>>::commit(
            &prover.whir_for_witness,
            &mut merlin,
            &prover.r1cs,
            w2,
            false,
        )
        .context("While committing to w2")?;

        vec![commitment_1, commitment_2]
    } else {
        vec![commitment_1]
    };
    drop(acir_witness_idx_to_value_map);

    #[cfg(test)]
    prover
        .r1cs
        .test_witness_satisfaction(&witness.iter().map(|w| w.unwrap()).collect::<Vec<_>>())
        .context("While verifying R1CS instance")?;
    drop(witness);

    let whir_r1cs_proof = <WhirR1CSScheme as WhirR1CSProver<H>>::prove(
        &prover.whir_for_witness,
        merlin,
        prover.r1cs,
        commitments,
    )
    .context("While proving R1CS instance")?;

    Ok(NoirProof { whir_r1cs_proof })
}

#[cfg(test)]
mod tests {}
