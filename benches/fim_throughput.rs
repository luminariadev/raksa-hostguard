use raksa_hostguard::audit::docker::{audit_compose, audit_dockerfile};
use raksa_hostguard::audit::host::{audit_sysctl_content, audit_systemd_content};
use raksa_hostguard::fim::hash::DEFAULT_MAX_FILE_BYTES;
use raksa_hostguard::fim::{
    create_snapshot_with_workers, default_worker_count, verify_snapshot_with_workers,
};
use raksa_hostguard::fix::{generate_fix_preview_content, FixKind};
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
    let workers = default_worker_count();
    let fim_iters = 5u32;

    // Single-worker create_snapshot
    let (baseline, _) = create_snapshot_with_workers(&roots, &excludes, DEFAULT_MAX_FILE_BYTES, 1)
        .expect("warmup 1w snapshot");
    let t_snap_1w = Instant::now();
    for _ in 0..fim_iters {
        let res = create_snapshot_with_workers(&roots, &excludes, DEFAULT_MAX_FILE_BYTES, 1)
            .expect("bench 1w create_snapshot");
        black_box(res);
    }
    let snap_1w_elapsed = t_snap_1w.elapsed().as_secs_f64();

    // Multi-worker parallel create_snapshot
    let _ = create_snapshot_with_workers(&roots, &excludes, DEFAULT_MAX_FILE_BYTES, workers)
        .expect("warmup parallel snapshot");
    let t_snap_par = Instant::now();
    for _ in 0..fim_iters {
        let res = create_snapshot_with_workers(&roots, &excludes, DEFAULT_MAX_FILE_BYTES, workers)
            .expect("bench parallel create_snapshot");
        black_box(res);
    }
    let snap_par_elapsed = t_snap_par.elapsed().as_secs_f64();

    // Multi-worker parallel verify_snapshot
    let _ = verify_snapshot_with_workers(&baseline, workers).expect("warmup parallel verify");
    let t_verify = Instant::now();
    for _ in 0..fim_iters {
        let findings =
            verify_snapshot_with_workers(&baseline, workers).expect("bench verify_snapshot");
        assert!(findings.is_empty());
        black_box(findings);
    }
    let verify_elapsed = t_verify.elapsed().as_secs_f64();

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

    let compose_sample = "\
services:
  api:
    image: nginx:1.27.4-alpine
    user: \"1000:1000\"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
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

    let sysctl_sample = "\
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
";
    let sysctl_iters = 10_000u32;
    let t_sysctl = Instant::now();
    for _ in 0..sysctl_iters {
        let f = audit_sysctl_content(black_box(sysctl_sample), "bench-sysctl.conf");
        black_box(f);
    }
    let sysctl_elapsed = t_sysctl.elapsed().as_secs_f64();

    let systemd_sample = "\
[Service]
User=raksa
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ExecStart=/usr/local/bin/worker
";
    let systemd_iters = 10_000u32;
    let t_systemd = Instant::now();
    for _ in 0..systemd_iters {
        let f = audit_systemd_content(black_box(systemd_sample), "bench.service");
        black_box(f);
    }
    let systemd_elapsed = t_systemd.elapsed().as_secs_f64();

    let fix_sample = "[Service]\nUser=root\nExecStart=/usr/bin/agent\n";
    let fix_iters = 5_000u32;
    let t_fix = Instant::now();
    for _ in 0..fix_iters {
        let p =
            generate_fix_preview_content(black_box(fix_sample), "bench.service", FixKind::Systemd)
                .expect("fix_preview");
        black_box(p);
    }
    let fix_elapsed = t_fix.elapsed().as_secs_f64();

    println!(
        "raksa-hostguard v{} benchmark (workers={})",
        raksa_hostguard::VERSION,
        workers
    );
    println!(
        "fim_create_snapshot_1w       : {} files ({:.2} MiB) x {} | {:.4}s | {:.1} files/s | {:.2} MiB/s",
        file_count,
        total_mib,
        fim_iters,
        snap_1w_elapsed,
        (file_count as f64 * f64::from(fim_iters)) / snap_1w_elapsed,
        (total_mib * f64::from(fim_iters)) / snap_1w_elapsed
    );
    println!(
        "fim_create_snapshot_parallel : {} files ({:.2} MiB) x {} | {:.4}s | {:.1} files/s | {:.2} MiB/s",
        file_count,
        total_mib,
        fim_iters,
        snap_par_elapsed,
        (file_count as f64 * f64::from(fim_iters)) / snap_par_elapsed,
        (total_mib * f64::from(fim_iters)) / snap_par_elapsed
    );
    println!(
        "fim_verify_snapshot_parallel : {} files ({:.2} MiB) x {} | {:.4}s | {:.1} files/s | {:.2} MiB/s",
        file_count,
        total_mib,
        fim_iters,
        verify_elapsed,
        (file_count as f64 * f64::from(fim_iters)) / verify_elapsed,
        (total_mib * f64::from(fim_iters)) / verify_elapsed
    );
    println!(
        "audit_dockerfile             : {} iters | {:.4}s | {:.1} ops/s",
        df_iters,
        df_elapsed,
        f64::from(df_iters) / df_elapsed
    );
    println!(
        "audit_compose                : {} iters | {:.4}s | {:.1} ops/s",
        cmp_iters,
        cmp_elapsed,
        f64::from(cmp_iters) / cmp_elapsed
    );
    println!(
        "audit_sysctl                 : {} iters | {:.4}s | {:.1} ops/s",
        sysctl_iters,
        sysctl_elapsed,
        f64::from(sysctl_iters) / sysctl_elapsed
    );
    println!(
        "audit_systemd                : {} iters | {:.4}s | {:.1} ops/s",
        systemd_iters,
        systemd_elapsed,
        f64::from(systemd_iters) / systemd_elapsed
    );
    println!(
        "fix_preview                  : {} iters | {:.4}s | {:.1} ops/s",
        fix_iters,
        fix_elapsed,
        f64::from(fix_iters) / fix_elapsed
    );
}
