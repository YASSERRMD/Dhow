//! Benchmarks for the codec data path.
//!
//! These measure the four things a transfer's throughput is actually made of:
//! the integrity digests every byte passes through twice, the fountain coding
//! that dominates everything else, and the frame serialization that runs once
//! per symbol.
//!
//! # What a number here means
//!
//! Throughput on the machine that ran it, and nothing more. These are not a
//! promise about a receiver's hardware, which is deliberately an old machine
//! kept off every network. They exist so a change that makes the data path
//! three times slower shows up as a number in a diff rather than as an operator
//! noticing a transfer now takes all afternoon.
//!
//! `docs/BENCHMARKS.md` records the committed baseline and how to compare
//! against it.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dhow_codec::blake3::{Blake3Hasher, blake3_digest};
use dhow_codec::chunker::{ChunkMap, ChunkParams};
use dhow_codec::crc32c::crc32c_digest;
use dhow_codec::fec::{self, FecParams};
use dhow_codec::frame::{Frame, FrameHeader, FrameType};
use std::hint::black_box;

/// Sizes the benchmarks run at.
///
/// 4 KiB is a small file, 256 KiB is a typical one, and 4 MiB is where the
/// per-call overhead has stopped mattering and the number is a rate. Anything
/// larger makes the suite too slow to run before a commit, which is the only
/// time it gets run.
const SIZES: &[usize] = &[4 * 1024, 256 * 1024, 4 * 1024 * 1024];

/// Deterministic test data.
///
/// Not random: a benchmark whose input changes between runs is a benchmark
/// whose numbers cannot be compared between runs, and the compression-free
/// primitives here do not care about entropy anyway.
fn data_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn bench_digests(c: &mut Criterion) {
    let mut group = c.benchmark_group("digest");

    for &size in SIZES {
        let data = data_of(size);
        group.throughput(Throughput::Bytes(size as u64));

        // Every byte of a payload passes through BLAKE3 at least twice: once
        // per block on the way out and once over the whole payload. It is the
        // integrity primitive most likely to be the bottleneck.
        group.bench_with_input(BenchmarkId::new("blake3", size), &data, |b, data| {
            b.iter(|| blake3_digest(black_box(data)));
        });

        // The streaming form is what `pack` uses, because it hashes a file
        // while writing it rather than reading the file twice. If it were much
        // slower than the one-shot, that decision would be wrong.
        group.bench_with_input(
            BenchmarkId::new("blake3_streaming", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut hasher = Blake3Hasher::new();
                    for chunk in data.chunks(64 * 1024) {
                        hasher.update(black_box(chunk));
                    }
                    hasher.finalize()
                });
            },
        );

        // CRC32C is the per-frame fast reject. It runs on every captured frame
        // including the ones that turn out to be garbage, so it is on the hot
        // path of a camera that is mostly seeing noise.
        group.bench_with_input(BenchmarkId::new("crc32c", size), &data, |b, data| {
            b.iter(|| crc32c_digest(black_box(data)));
        });
    }

    group.finish();
}

fn bench_chunker(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunker");

    for &size in SIZES {
        let data = data_of(size);
        group.throughput(Throughput::Bytes(size as u64));

        // extract_block per block, which is what the pipeline does before it
        // hands each block to the coder. The chunker is arithmetic over
        // offsets, so this measures the slicing rather than a copy of the
        // payload - which is the point: if it ever starts copying, the number
        // moves.
        group.bench_with_input(
            BenchmarkId::new("extract_blocks", size),
            &data,
            |b, data| {
                let params = ChunkParams::new(data.len() as u64, 4, 1024).unwrap();
                let chunker = ChunkMap::new(params).unwrap();
                b.iter(|| {
                    for block in 0..chunker.block_count() {
                        black_box(chunker.extract_block(black_box(data), block).unwrap());
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_fec(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec");
    // RaptorQ dominates a transfer's cost and is quadratic-ish in block size,
    // so the largest size here is smaller than the others: at 4 MiB a single
    // encode takes long enough that criterion's default sample count turns
    // this into a minutes-long benchmark nobody runs.
    let sizes: &[usize] = &[4 * 1024, 64 * 1024, 512 * 1024];

    for &size in sizes {
        let data = data_of(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encode", size), &data, |b, data| {
            let params = FecParams::new();
            b.iter(|| {
                let encoder = fec::encode(black_box(data), &params);
                // Producing the packets is the work; constructing the encoder
                // alone would measure almost nothing.
                black_box(encoder.packets(0))
            });
        });

        // Decode from exactly the packets the encoder produced, which is the
        // best case. A real receiver decodes from a lossy subset and pays more,
        // but the lossy case depends on which packets were lost and would make
        // the number depend on the loss pattern rather than on the code.
        group.bench_with_input(BenchmarkId::new("decode", size), &data, |b, data| {
            let params = FecParams::new();
            let encoder = fec::encode(data, &params);
            let packets = encoder.packets(0);
            let config = encoder.config();

            b.iter(|| black_box(fec::decode(black_box(&packets), &config).unwrap()));
        });
    }

    group.finish();
}

fn bench_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame");

    // One symbol, which is what a frame carries. The interesting number is
    // per-frame cost, not per-byte: a 1 GiB transfer at a 1320-byte symbol is
    // 800,000 frames, and a microsecond each is most of a second.
    for &symbol_size in &[256usize, 1024, 1320] {
        let payload = data_of(symbol_size);
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(
            BenchmarkId::new("serialize", symbol_size),
            &payload,
            |b, payload| {
                b.iter(|| {
                    let header =
                        FrameHeader::new(FrameType::Repair, [0x42; 16], 0, 0, black_box(payload));
                    // Frame::build computes the MAC, which is the per-frame
                    // cost that matters: it runs once for every symbol in a
                    // transfer, on both sides.
                    black_box(Frame::build(&header, payload, &[0xAB; 32]).to_vec())
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("parse", symbol_size),
            &payload,
            |b, payload| {
                let header = FrameHeader::new(FrameType::Repair, [0x42; 16], 0, 0, payload);
                let bytes = Frame::build(&header, payload, &[0xAB; 32]).to_vec();

                b.iter(|| black_box(Frame::from_bytes(black_box(&bytes), &[0xAB; 32]).unwrap()));
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_digests,
    bench_chunker,
    bench_fec,
    bench_frame
);
criterion_main!(benches);
