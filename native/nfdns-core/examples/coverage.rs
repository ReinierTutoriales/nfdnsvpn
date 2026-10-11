//! Blocking coverage of a set of lists, for scripts/validate-lists.sh.
//! Usage: coverage <labelled domains file> <list file>...
//! The labelled file has `label<TAB>domain` lines; prints, per label, how many are blocked and
//! which are not (or, for labels starting with "allow:", which are blocked by mistake).
use nfdns::filter::FilterBuilder;
use std::collections::BTreeMap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut builder = FilterBuilder::default();
    for path in &args[2..] {
        builder.add_reader(std::io::BufReader::new(std::fs::File::open(path).expect("list"))).expect("read");
    }
    let filter = builder.build();
    let mut groups: BTreeMap<String, (usize, Vec<String>, Vec<String>)> = BTreeMap::new();
    for line in std::fs::read_to_string(&args[1]).expect("domains").lines() {
        let Some((label, domain)) = line.split_once('\t') else { continue };
        let entry = groups.entry(label.to_string()).or_default();
        entry.0 += 1;
        if filter.is_blocked(domain) { entry.1.push(domain.to_string()) } else { entry.2.push(domain.to_string()) }
    }
    println!("lists: {} domains, {} IPs", filter.rule_count(), filter.ip_count());
    for (label, (total, blocked, passed)) in groups {
        if let Some(name) = label.strip_prefix("allow:") {
            println!("{name}: {}/{total} blocked by mistake {:?}", blocked.len(), blocked);
        } else {
            println!(
                "{label}: {}/{total} blocked ({:.0}%); missed {:?}",
                blocked.len(),
                100.0 * blocked.len() as f64 / total as f64,
                passed
            );
        }
    }
}
