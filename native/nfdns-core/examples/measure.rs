//! Loads real blocklists and reports rule count, build time, filter memory and lookup speed.
//! Usage: cargo run --release --example measure -- <list file>...
use nfdns::filter::FilterBuilder;
use std::time::Instant;

fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status").ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:"))
            .and_then(|l| l.split_whitespace().nth(1)?.parse().ok()))
        .unwrap_or(0)
}

fn main() {
    let before = rss_kb();
    let start = Instant::now();
    let mut builder = FilterBuilder::default();
    for path in std::env::args().skip(1) {
        builder.add_list(&std::fs::read_to_string(&path).expect("list"));
    }
    let filter = builder.build();
    let built = start.elapsed();
    let names = ["pubads.g.doubleclick.net", "www.google.com", "ads.unity3d.com", "a.b.c.d.example.org"];
    let start = Instant::now();
    let mut blocked = 0;
    for i in 0..1_000_000 {
        blocked += filter.is_blocked(names[i % names.len()]) as u32;
    }
    let lookup = start.elapsed() / 1_000_000;
    println!("rules={} filter={} KB build={:?} rss_delta={} KB lookup={:?} blocked={}", filter.rule_count(), filter.memory_bytes() / 1024, built, rss_kb() - before, lookup, blocked);
    for n in names { println!("  {n}: {}", filter.is_blocked(n)); }
}
