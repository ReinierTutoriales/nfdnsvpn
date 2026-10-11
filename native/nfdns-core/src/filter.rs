//! Domain filter compiled from DNS blocklists.
//!
//! Only rules that a resolver can apply are kept: without decrypting traffic the URL is never
//! visible, so path, option and cosmetic rules are dropped.

/// Sorted, deduplicated lowercase domains packed into one buffer: about 25 bytes per domain
/// instead of the ~70 a `HashSet<String>` costs, which matters on a 2 GB TV.
#[derive(Default)]
pub struct DomainSet {
    data: Vec<u8>,
    ends: Vec<u32>,
}

impl DomainSet {
    fn from_collector(collector: Collector) -> Self {
        let Collector { data: raw, mut spans } = collector;
        let text = |&(start, length): &(u32, u32)| &raw[start as usize..(start + length) as usize];
        spans.sort_unstable_by(|a, b| text(a).cmp(text(b)));
        spans.dedup_by(|a, b| text(a) == text(b));
        let mut data = Vec::with_capacity(spans.iter().map(|&(_, length)| length as usize).sum());
        let mut ends = Vec::with_capacity(spans.len());
        for span in &spans {
            data.extend_from_slice(text(span));
            ends.push(data.len() as u32);
        }
        DomainSet { data, ends }
    }

    fn get(&self, index: usize) -> &[u8] {
        let start = if index == 0 { 0 } else { self.ends[index - 1] as usize };
        &self.data[start..self.ends[index] as usize]
    }

    pub fn contains(&self, domain: &[u8]) -> bool {
        let (mut low, mut high) = (0, self.ends.len());
        while low < high {
            let mid = (low + high) / 2;
            match self.get(mid).cmp(domain) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    fn len(&self) -> usize {
        self.ends.len()
    }

    fn memory_bytes(&self) -> usize {
        self.data.capacity() + self.ends.capacity() * 4
    }

    /// True when `domain` or one of its parent domains is in the set.
    fn contains_suffix_of(&self, domain: &[u8]) -> bool {
        let mut rest = domain;
        loop {
            if self.contains(rest) {
                return true;
            }
            match rest.iter().position(|&b| b == b'.') {
                Some(dot) => rest = &rest[dot + 1..],
                None => return false,
            }
        }
    }
}

pub struct Filter {
    /// `||domain^`: the domain and every subdomain.
    block_suffix: DomainSet,
    /// hosts lines and bare domains: that exact name only.
    block_exact: DomainSet,
    allow_suffix: DomainSet,
    allow_exact: DomainSet,
}

impl Filter {
    /// Exceptions always win over blocks, as in AdGuard and uBlock Origin.
    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.as_bytes();
        if self.allow_exact.contains(domain) || self.allow_suffix.contains_suffix_of(domain) {
            return false;
        }
        self.block_exact.contains(domain) || self.block_suffix.contains_suffix_of(domain)
    }

    /// Number of blocking rules after deduplication.
    pub fn rule_count(&self) -> usize {
        self.block_suffix.len() + self.block_exact.len()
    }

    /// Heap held by the compiled filter (the build itself peaks higher).
    pub fn memory_bytes(&self) -> usize {
        [&self.block_suffix, &self.block_exact, &self.allow_suffix, &self.allow_exact]
            .iter()
            .map(|set| set.memory_bytes())
            .sum()
    }
}

/// Domains as they are parsed, packed in one buffer: about 8 bytes of overhead per domain instead
/// of the ~40 of a `String`, which keeps the build peak low on a 2 GB TV.
#[derive(Default)]
struct Collector {
    data: Vec<u8>,
    spans: Vec<(u32, u32)>,
}

impl Collector {
    fn push(&mut self, domain: &str) {
        self.spans.push((self.data.len() as u32, domain.len() as u32));
        self.data.extend_from_slice(domain.as_bytes());
    }
}

#[derive(Default)]
pub struct FilterBuilder {
    block_suffix: Collector,
    block_exact: Collector,
    allow_suffix: Collector,
    allow_exact: Collector,
}

enum Rule {
    BlockSuffix(String),
    BlockExact(String),
    AllowSuffix(String),
    AllowExact(String),
}

impl FilterBuilder {
    /// Accepts adblock (`||domain^`), hosts (`0.0.0.0 domain`) and one-domain-per-line lists.
    pub fn add_list(&mut self, text: &str) {
        for line in text.lines() {
            self.add_line(line);
        }
    }

    /// Same as [`FilterBuilder::add_list`], reading line by line: the list text is never held
    /// in memory as a whole. Lines that are not valid UTF-8 are skipped.
    pub fn add_reader<R: std::io::BufRead>(&mut self, mut reader: R) -> std::io::Result<()> {
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                return Ok(());
            }
            if let Ok(text) = std::str::from_utf8(&line) {
                self.add_line(text);
            }
        }
    }

    fn add_line(&mut self, line: &str) {
        for rule in parse_line(line) {
            match rule {
                Rule::BlockSuffix(d) => self.block_suffix.push(&d),
                Rule::BlockExact(d) => self.block_exact.push(&d),
                Rule::AllowSuffix(d) => self.allow_suffix.push(&d),
                Rule::AllowExact(d) => self.allow_exact.push(&d),
            }
        }
    }

    pub fn build(self) -> Filter {
        Filter {
            block_suffix: DomainSet::from_collector(self.block_suffix),
            block_exact: DomainSet::from_collector(self.block_exact),
            allow_suffix: DomainSet::from_collector(self.allow_suffix),
            allow_exact: DomainSet::from_collector(self.allow_exact),
        }
    }
}

/// Lowercase domain without a trailing dot, or `None` when it is not a plain hostname
/// (wildcards, paths, ports, IP literals and single labels are rejected).
pub fn normalize_domain(raw: &str) -> Option<String> {
    let domain = raw.trim_end_matches('.').to_ascii_lowercase();
    if domain.len() > 253 || !domain.contains('.') {
        return None;
    }
    let valid_labels = domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    let ip_literal = domain.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    (valid_labels && !ip_literal).then_some(domain)
}

/// Options that keep the rule meaningful for a resolver; anything else (`$third-party`,
/// `$denyallow`, `$dnstype`, `$badfilter`...) changes its scope, so the rule is skipped.
fn options_apply_to_dns(options: &str) -> bool {
    options.split(',').all(|option| matches!(option.trim(), "important" | "all" | "document" | "doc"))
}

fn parse_adblock(body: &str) -> Option<String> {
    let body = body.strip_prefix("||")?;
    let (domain, rest) = match body.find('^') {
        Some(caret) => (&body[..caret], &body[caret + 1..]),
        None => (body, ""),
    };
    let rest_ok = rest.is_empty() || rest.strip_prefix('$').is_some_and(options_apply_to_dns);
    if !rest_ok {
        return None;
    }
    normalize_domain(domain)
}

const HOSTS_ADDRESSES: [&str; 5] = ["0.0.0.0", "127.0.0.1", "::", "::1", "0"];
const HOSTS_IGNORED: [&str; 6] = ["localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback"];

fn parse_line(line: &str) -> Vec<Rule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
        return Vec::new();
    }
    // Cosmetic and scriptlet rules: page-level, not network-level.
    if line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#") || line.contains("#%#") {
        return Vec::new();
    }
    if let Some(exception) = line.strip_prefix("@@") {
        if exception.starts_with("||") {
            return parse_adblock(exception).map(Rule::AllowSuffix).into_iter().collect();
        }
        return normalize_domain(exception).map(Rule::AllowExact).into_iter().collect();
    }
    if line.starts_with("||") {
        return parse_adblock(line).map(Rule::BlockSuffix).into_iter().collect();
    }
    let line = line.split('#').next().unwrap_or("").trim();
    let mut tokens = line.split_whitespace();
    let Some(first) = tokens.next() else { return Vec::new() };
    if HOSTS_ADDRESSES.contains(&first) {
        return tokens
            .filter(|token| !HOSTS_IGNORED.contains(token))
            .filter_map(normalize_domain)
            .map(Rule::BlockExact)
            .collect();
    }
    if tokens.next().is_none() {
        return normalize_domain(first).map(Rule::BlockExact).into_iter().collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(list: &str) -> Filter {
        let mut builder = FilterBuilder::default();
        builder.add_list(list);
        builder.build()
    }

    #[test]
    fn adblock_rules_block_subdomains() {
        let f = filter("||doubleclick.net^\n");
        assert!(f.is_blocked("doubleclick.net"));
        assert!(f.is_blocked("pubads.g.doubleclick.net"));
        assert!(!f.is_blocked("notdoubleclick.net"));
        assert!(!f.is_blocked("net"));
    }

    #[test]
    fn hosts_and_plain_lines_are_exact() {
        let f = filter("0.0.0.0 ads.example.com tracker.example.com # comment\n127.0.0.1 localhost\nmetrics.example.org\n");
        assert!(f.is_blocked("ads.example.com"));
        assert!(f.is_blocked("tracker.example.com"));
        assert!(f.is_blocked("metrics.example.org"));
        assert!(!f.is_blocked("sub.ads.example.com"));
        assert!(!f.is_blocked("example.com"));
        assert!(!f.is_blocked("localhost"));
        assert_eq!(f.rule_count(), 3);
    }

    #[test]
    fn exceptions_win() {
        let f = filter("||example.com^\n@@||safe.example.com^\n@@exact.example.com\n");
        assert!(f.is_blocked("ads.example.com"));
        assert!(!f.is_blocked("safe.example.com"));
        assert!(!f.is_blocked("cdn.safe.example.com"));
        assert!(!f.is_blocked("exact.example.com"));
        assert!(f.is_blocked("sub.exact.example.com"));
    }

    #[test]
    fn skips_rules_a_resolver_cannot_apply() {
        let f = filter(concat!(
            "! comment\n[Adblock Plus 2.0]\n",
            "example.com##.banner\n",
            "||path.example.com/ads/*\n",
            "||thirdparty.example.com^$third-party\n",
            "||wild*.example.com^\n",
            "/banner/*\n",
            "||1.2.3.4^\n",
            "||important.example.com^$important\n",
        ));
        assert_eq!(f.rule_count(), 1);
        assert!(f.is_blocked("important.example.com"));
        assert!(!f.is_blocked("thirdparty.example.com"));
    }

    #[test]
    fn normalizes_case_and_trailing_dot() {
        let f = filter("||Ads.Example.COM.^\n");
        assert!(f.is_blocked("ads.example.com"));
    }

    #[test]
    fn reading_line_by_line_matches_reading_the_whole_text() {
        let list = "! comment\n||a.example^\r\n0.0.0.0 b.example\nc.example\n@@||ok.a.example^\n||d.example^";
        let mut builder = FilterBuilder::default();
        builder.add_reader(std::io::Cursor::new(list.as_bytes())).unwrap();
        let mut invalid = b"||e.example^\n".to_vec();
        invalid.extend_from_slice(&[0xFF, 0xFE, b'\n']);
        invalid.extend_from_slice(b"||f.example^\n");
        builder.add_reader(std::io::Cursor::new(invalid)).unwrap();
        let f = builder.build();
        assert_eq!(f.rule_count(), 6);
        assert!(f.is_blocked("x.a.example") && f.is_blocked("b.example") && f.is_blocked("d.example"));
        assert!(!f.is_blocked("ok.a.example"));
        assert!(f.is_blocked("f.example"));
    }

    #[test]
    fn deduplicates_across_lists() {
        let mut builder = FilterBuilder::default();
        builder.add_list("||a.example^\n||b.example^\n");
        builder.add_list("||a.example^\n");
        assert_eq!(builder.build().rule_count(), 2);
    }
}
