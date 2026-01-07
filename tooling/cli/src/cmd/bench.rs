use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{hash::HashFunction, NoirProof, NoirProofScheme, Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    provekit_verifier::Verify,
    serde::Serialize,
    std::{
        fs,
        path::{Path, PathBuf},
        str::FromStr,
        time::Instant,
    },
    tracing::instrument,
};

const DEFAULT_HASHES: &[&str] = &["sha2", "sha3", "blake3", "skyscraper_v2", "poseidon2"];

/// Benchmark proving and verification for multiple hash suites.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "bench")]
pub struct Args {
    /// path to the compiled Noir program (.json)
    #[argh(option, long = "program")]
    program_path: PathBuf,

    /// path to the prover input TOML
    #[argh(option, long = "input")]
    input_path: PathBuf,

    /// comma separated list of hash functions (default: all)
    #[argh(option, long = "hashes")]
    hashes: Option<String>,

    /// number of runs per hash
    #[argh(option, long = "runs", default = "5")]
    runs: usize,

    /// path to write JSON summary (optional)
    #[argh(option, long = "summary-json")]
    summary_json: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct StageStats {
    avg_time_seconds: f64,
    var_time_seconds: f64,
    avg_rss_mb:       f64,
    max_rss_mb:       f64,
    runs:             Vec<f64>,
}

#[derive(Debug, Serialize)]
struct HashStats {
    hash:   String,
    prove:  StageStats,
    verify: StageStats,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        ensure_inputs_exist(&self.program_path, &self.input_path)?;
        let hashes = parse_hashes(self.hashes.as_deref())?;
        let mut results = Vec::new();

        for hash in hashes {
            let stats = benchmark_hash(&self.program_path, &self.input_path, hash, self.runs)?;
            print_summary(&stats);
            results.push(stats);
        }

        if let Some(path) = &self.summary_json {
            let json = serde_json::to_string_pretty(&results)?;
            fs::write(path, json).context("while writing summary JSON")?;
        }

        Ok(())
    }
}

fn ensure_inputs_exist(program: &Path, input: &Path) -> Result<()> {
    anyhow::ensure!(program.is_file(), "program {:?} does not exist", program);
    anyhow::ensure!(input.is_file(), "input {:?} does not exist", input);
    Ok(())
}

fn parse_hashes(input: Option<&str>) -> Result<Vec<HashFunction>> {
    let entries: Vec<&str> = input
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_else(|| DEFAULT_HASHES.iter().copied().collect());

    entries
        .into_iter()
        .map(HashFunction::from_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!(e))
}

fn benchmark_hash(
    program: &Path,
    input: &Path,
    hash: HashFunction,
    runs: usize,
) -> Result<HashStats> {
    let scheme = NoirProofScheme::from_file_with_hash(program, hash)
        .with_context(|| format!("while building scheme for hash {hash}"))?;

    let mut prove_times = Vec::with_capacity(runs);
    let mut prove_rss = Vec::with_capacity(runs);
    let mut verify_times = Vec::with_capacity(runs);
    let mut verify_rss = Vec::with_capacity(runs);

    for run_idx in 0..runs {
        tracing::info!(%hash, run = run_idx + 1, "proving");
        let (proof, time, rss) = run_prove(&scheme, input)?;
        prove_times.push(time);
        prove_rss.push(rss);

        tracing::info!(%hash, run = run_idx + 1, "verifying");
        let (time_v, rss_v) = run_verify(&scheme, &proof)?;
        verify_times.push(time_v);
        verify_rss.push(rss_v);
    }

    Ok(HashStats {
        hash:   hash.as_str().to_string(),
        prove:  StageStats::new(&prove_times, &prove_rss),
        verify: StageStats::new(&verify_times, &verify_rss),
    })
}

fn run_prove(scheme: &NoirProofScheme, input_path: &Path) -> Result<(NoirProof, f64, f64)> {
    let hash = scheme.hash_function;
    let prover = Prover::from_noir_proof_scheme(scheme.clone());
    tracing::debug!(%hash, "Proving with hash");
    let start = Instant::now();
    let proof = prover.prove(input_path)?;
    let duration = start.elapsed().as_secs_f64();
    let rss = current_rss_mb();
    Ok((proof, duration, rss))
}

fn run_verify(scheme: &NoirProofScheme, proof: &NoirProof) -> Result<(f64, f64)> {
    let hash = scheme.hash_function;
    let mut verifier = Verifier::from_noir_proof_scheme(scheme.clone());
    tracing::debug!(%hash, "Verifying with hash");
    let start = Instant::now();
    verifier.verify(proof)?;
    let duration = start.elapsed().as_secs_f64();
    let rss = current_rss_mb();
    Ok((duration, rss))
}

impl StageStats {
    fn new(times: &[f64], rss: &[f64]) -> Self {
        let avg_time = mean(times);
        let var_time = variance(times, avg_time);
        let avg_rss = mean(rss);
        let max_rss = rss.iter().copied().fold(0.0, f64::max);
        Self {
            avg_time_seconds: avg_time,
            var_time_seconds: var_time,
            avg_rss_mb:       avg_rss,
            max_rss_mb:       max_rss,
            runs:             times.to_vec(),
        }
    }
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().copied().sum::<f64>() / values.len() as f64
}

fn variance(values: &[f64], mean: f64) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    values
        .iter()
        .map(|v| {
            let diff = v - mean;
            diff * diff
        })
        .sum::<f64>()
        / values.len() as f64
}

fn current_rss_mb() -> f64 {
    use sysinfo::{Pid, System};

    let pid: Pid = match sysinfo::get_current_pid() {
        Ok(pid) => pid,
        Err(_) => return 0.0,
    };
    let mut system = System::new();
    system.refresh_process(pid);
    if let Some(process) = system.process(pid) {
        // memory() returns kilobytes
        return process.memory() as f64 / 1024.0;
    }
    0.0
}

fn print_summary(stats: &HashStats) {
    println!(
        "\nHash: {}\n  Prove avg {:.2}s (var {:.4}), avg RSS {:.1} MiB (max {:.1})\n  Verify avg \
         {:.2}s (var {:.4}), avg RSS {:.1} MiB (max {:.1})",
        stats.hash,
        stats.prove.avg_time_seconds,
        stats.prove.var_time_seconds,
        stats.prove.avg_rss_mb,
        stats.prove.max_rss_mb,
        stats.verify.avg_time_seconds,
        stats.verify.var_time_seconds,
        stats.verify.avg_rss_mb,
        stats.verify.max_rss_mb,
    );
}
