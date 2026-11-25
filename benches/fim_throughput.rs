use raksa_hostguard::audit::docker::{audit_compose, audit_dockerfile};
use raksa_hostguard::fim::hash::DEFAULT_MAX_FILE_BYTES;
use raksa_hostguard::fim::{create_snapshot, verify_snapshot};
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;
use tempfile::tempdir;

fn main() {
    let file_count = 200usize;
    let total_target_bytes = 16usize * 1024 * 1024;
    let base_chunk = total_target_bytes / file_count;
    let remainder = total_target_bytes % file_count;

    let dir = tempdir().expect("create benchmark tempdir");
    let root = dir.path().join("fim_corpus");
    fs::create_dir_all(&root).expect("create corpus dir");

    for idx in 0..file_count {
        let len = if idx == file_count - 1 {
            base_chunk + remainder
        } else {
            base_chunk
        };
        let mut payload = vec![b'A' + (idx % 26) as u8; len];
        // Inject variation across blocks so buffers are distinct.
        if len > 16 {
            payload[0] = (idx & 0xff) as u8;
            payload[len - 1] = ((idx * 7) & 0xff) as u8;
        }
        let path = root.join(format!("config_{idx:03}.dat"));
        fs::write(&path, &payload).expect("write benchmark file");
    }

    let roots = vec![PathBuf::from(&root)];
    let excludes: Vec<String> = Vec::new();
    let total_mib = total_target_bytes as f64 / (1024.0 * 1024.0);

    // Warmup pass for create_snapshot and capture baseline.
    let (baseline, _) =
        create_snapshot(&roots, &excludes, DEFAULT_MAX_FILE_BYTES).expect("warmup create_snapshot");

    let fim_iters = 5u32;
    let t_snap = Instant::now();
    for _ in 0..fim_iters {
        let res = create_snapshot(&roots, &excludes, DEFAULT_MAX_FILE_BYTES)
            .expect("bench create_snapshot");
        black_box(res);
    }
    let snap_elapsed = t_snap.elapsed().as_secs_f64();
    let snap_files_per_sec = (file_count as f64 * f64::from(fim_iters)) / snap_elapsed;
    let snap_mib_per_sec = (total_mib * f64::from(fim_iters)) / snap_elapsed;

    // Warmup verify_snapshot.
    let _ = verify_snapshot(&baseline).expect("warmup verify_snapshot");

    let t_verify = Instant::now();
    for _ in 0..fim_iters {
        let findings = verify_snapshot(&baseline).expect("bench verify_snapshot");
        assert!(findings.is_empty());
        black_box(findings);
    }
    let verify_elapsed = t_verify.elapsed().as_secs_f64();
    let verify_files_per_sec = (file_count as f64 * f64::from(fim_iters)) / verify_elapsed;
    let verify_mib_per_sec = (total_mib * f64::from(fim_iters)) / verify_elapsed;

    let dockerfile_sample = "\
FROM rust:1.86-alpine AS builder
WORKDIR /src
COPY . .
RUN echo ok
FROM gcr.io/distroless/static-debian12:nonroot@sha256:0000000000000000000000000000000000000000000000000000000000000000
ENV DB_PASSWORD=hardcoded_literal_secret
ADD https://example.com/pkg.tar.gz /tmp/pkg.tar.gz
USER nonroot
";
    let df_iters = 10_000u32;
    let t_df = Instant::now();
    for _ in 0..df_iters {
        let f = audit_dockerfile(black_box(dockerfile_sample), "bench.Dockerfile");
        black_box(f);
    }
    let df_elapsed = t_df.elapsed().as_secs_f64();
    let df_ops_per_sec = f64::from(df_iters) / df_elapsed;

    let compose_sample = "\
services:
  api:
    image: nginx:1.27.4-alpine
    user: \"1000:1000\"
    cap_drop:
      - ALL
    environment:
      APP_ENV: production
      API_TOKEN: ${API_TOKEN}
";
    let cmp_iters = 5_000u32;
    let t_cmp = Instant::now();
    for _ in 0..cmp_iters {
        let f = audit_compose(black_box(compose_sample), "bench-compose.yml").expect("yaml");
        black_box(f);
    }
    let cmp_elapsed = t_cmp.elapsed().as_secs_f64();
    let cmp_ops_per_sec = f64::from(cmp_iters) / cmp_elapsed;

    println!("raksa-hostguard v{} benchmark", raksa_hostguard::VERSION);
    println!(
        "fim_create_snapshot  : {} files ({:.2} MiB) x {} | {:.4}s | {:.1} files/s | {:.2} MiB/s",
        file_count, total_mib, fim_iters, snap_elapsed, snap_files_per_sec, snap_mib_per_sec
    );
    println!(
        "fim_verify_snapshot  : {} files ({:.2} MiB) x {} | {:.4}s | {:.1} files/s | {:.2} MiB/s",
        file_count, total_mib, fim_iters, verify_elapsed, verify_files_per_sec, verify_mib_per_sec
    );
    println!(
        "audit_dockerfile     : {} iters | {:.4}s | {:.1} ops/s",
        df_iters, df_elapsed, df_ops_per_sec
    );
    println!(
        "audit_compose        : {} iters | {:.4}s | {:.1} ops/s",
        cmp_iters, cmp_elapsed, cmp_ops_per_sec
    );
}
