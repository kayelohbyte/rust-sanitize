//! End-to-end benchmark for the streaming scanner and archive processor.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sanitize_engine::category::Category;
use sanitize_engine::generator::HmacGenerator;
use sanitize_engine::processor::archive::ArchiveProcessor;
use sanitize_engine::processor::ProcessorRegistry;
use sanitize_engine::scanner::{ScanConfig, ScanPattern, StreamScanner};
use sanitize_engine::store::MappingStore;
use std::io::Cursor;
use std::sync::Arc;

/// Build a reusable scanner + store for benchmarks.
fn build_scanner(chunk_size: usize) -> Arc<StreamScanner> {
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    let store = Arc::new(MappingStore::new(gen, None));
    let patterns = vec![
        ScanPattern::from_regex(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            Category::Email,
            "email",
        )
        .unwrap(),
        ScanPattern::from_regex(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            Category::IpV4,
            "ipv4",
        )
        .unwrap(),
        ScanPattern::from_regex(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            Category::Uuid,
            "uuid",
        )
        .unwrap(),
    ];
    let config = ScanConfig::new(chunk_size, 4096);
    Arc::new(StreamScanner::new(patterns, store, config).unwrap())
}

/// Generate synthetic input with embedded secrets every ~200 bytes.
fn generate_input(size: usize) -> Vec<u8> {
    let line = "server=192.168.1.42 user=alice@corp.com id=550e8400-e29b-41d4-a716-446655440000 lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor\n";
    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        let remaining = size - buf.len();
        if remaining >= line.len() {
            buf.extend_from_slice(line.as_bytes());
        } else {
            buf.extend_from_slice(&line.as_bytes()[..remaining]);
        }
    }
    buf.truncate(size);
    buf
}

// ---------------------------------------------------------------------------
// Streaming scanner benchmarks
// ---------------------------------------------------------------------------

fn bench_scan_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_throughput");

    for &size_mib in &[1, 16, 64] {
        let size = size_mib * 1024 * 1024;
        let input = generate_input(size);
        let scanner = build_scanner(1024 * 1024);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("default_chunk", format!("{size_mib}MiB")),
            &input,
            |b, input| {
                b.iter(|| {
                    let mut output = Vec::with_capacity(input.len());
                    scanner.scan_reader(input.as_slice(), &mut output).unwrap();
                });
            },
        );
    }
    group.finish();
}

fn bench_chunk_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_size_impact");
    let size = 16 * 1024 * 1024; // 16 MiB
    let input = generate_input(size);

    for &chunk_kib in &[64, 256, 1024, 4096] {
        let chunk_size = chunk_kib * 1024;
        let scanner = build_scanner(chunk_size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("16MiB_input", format!("{chunk_kib}KiB")),
            &input,
            |b, input| {
                b.iter(|| {
                    let mut output = Vec::with_capacity(input.len());
                    scanner.scan_reader(input.as_slice(), &mut output).unwrap();
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Archive processing benchmark
// ---------------------------------------------------------------------------

fn bench_tar_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("tar_processing");

    // Build a tar archive with N files of 64 KiB each.
    for &file_count in &[10, 50] {
        let file_size = 64 * 1024;
        let file_data = generate_input(file_size);

        // Create tar in memory.
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for i in 0..file_count {
                let mut header = tar::Header::new_gnu();
                header.set_size(file_data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("file_{i}.log"), file_data.as_slice())
                    .unwrap();
            }
            builder.finish().unwrap();
        }

        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let scanner = build_scanner(1024 * 1024);
        let registry = Arc::new(ProcessorRegistry::new());
        let archive_proc = ArchiveProcessor::new(registry, scanner, store, vec![]);

        group.throughput(Throughput::Bytes(tar_buf.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("files", file_count),
            &tar_buf,
            |b, tar_buf| {
                b.iter(|| {
                    let reader = Cursor::new(tar_buf);
                    let mut output = Vec::with_capacity(tar_buf.len());
                    archive_proc.process_tar(reader, &mut output).unwrap();
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_scan_throughput,
    bench_chunk_sizes,
    bench_tar_processing,
);
criterion_main!(benches);
