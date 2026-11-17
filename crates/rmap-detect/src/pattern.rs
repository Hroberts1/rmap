//! A small byte-oriented pattern language for match rules.
//!
//! It is a subset of familiar regular-expression syntax, compiled to a
//! program and run on a Pike VM (a breadth-first NFA simulation). Matching
//! time is `O(input × program)`: there is no backtracking, so no pattern can
//! blow up on hostile input. Patterns work on raw bytes, so they can match
//! binary protocols as well as text banners.
//!
//! | Syntax | Meaning |
//! |---|---|
//! | `abc` | literal bytes (non-ASCII characters match their UTF-8 bytes) |
//! | `.` | any byte except `\n` (any byte at all with the `s` flag) |
//! | `[a-z_.]`, `[^\r\n]` | byte class, negated class |
//! | `\d \w \s` / `\D \W \S` | ASCII digit, word byte, whitespace / their complements |
//! | `\r \n \t \0 \xHH` | control bytes, any byte in hex |
//! | `\.` `\(` … | any other punctuation, escaped |
//! | `( )` | capture group, numbered from 1 by its opening parenthesis |
//! | `(?: )` | group without capture |
//! | `a\|b` | alternation, leftmost alternative preferred |
//! | `* + ?` | repetition (greedy); add `?` for the lazy form (`*?`) |
//! | `{n}` `{n,}` `{n,m}` | counted repetition, `n`/`m` ≤ 255 |
//! | `^` | start of the response |
//! | `$` | end of a line: before `\r\n`, before `\n`, or at the end |
//! | `(?i)` `(?s)` `(?is)` | flags, only at the very start: case-insensitive ASCII; `.` matches `\n` |
//!
//! The search is unanchored unless the pattern starts with `^`. When several
//! matches are possible, the leftmost one wins, and within it the same
//! preferences a backtracking engine would make (greedy takes the most).

use std::fmt;

/// Longest pattern source accepted.
const MAX_PATTERN_LEN: usize = 4096;
/// Deepest group nesting accepted.
const MAX_DEPTH: usize = 32;
/// Largest `{n,m}` bound.
const MAX_REPEAT: u32 = 255;
/// Most instructions a compiled pattern may have.
const MAX_PROGRAM: usize = 20_000;
/// Most capture groups a pattern may have.
pub const MAX_GROUPS: usize = 9;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError {
    pub offset: usize,
    pub message: String,
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.message, self.offset)
    }
}

impl std::error::Error for PatternError {}

/// A set of bytes, as a 256-bit bitmap.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct ByteSet([u64; 4]);

impl ByteSet {
    fn insert(&mut self, b: u8) {
        self.0[(b >> 6) as usize] |= 1 << (b & 63);
    }
    fn insert_range(&mut self, lo: u8, hi: u8) {
        for b in lo..=hi {
            self.insert(b);
        }
    }
    fn contains(&self, b: u8) -> bool {
        self.0[(b >> 6) as usize] & (1 << (b & 63)) != 0
    }
    fn union(&mut self, other: &ByteSet) {
        for (a, b) in self.0.iter_mut().zip(other.0) {
            *a |= b;
        }
    }
    fn negate(&mut self) {
        for a in &mut self.0 {
            *a = !*a;
        }
    }
    fn fold_case(&mut self) {
        for b in b'a'..=b'z' {
            if self.contains(b) || self.contains(b.to_ascii_uppercase()) {
                self.insert(b);
                self.insert(b.to_ascii_uppercase());
            }
        }
    }
    fn digit() -> Self {
        let mut s = Self::default();
        s.insert_range(b'0', b'9');
        s
    }
    fn word() -> Self {
        let mut s = Self::digit();
        s.insert_range(b'a', b'z');
        s.insert_range(b'A', b'Z');
        s.insert(b'_');
        s
    }
    fn space() -> Self {
        let mut s = Self::default();
        for b in [b' ', b'\t', b'\n', b'\r', 0x0b, 0x0c] {
            s.insert(b);
        }
        s
    }
}

impl fmt::Debug for ByteSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ByteSet(..)")
    }
}

#[derive(Debug, Clone)]
enum Node {
    Empty,
    Set(ByteSet),
    Bol,
    Eol,
    Group(Option<usize>, Box<Node>),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
    },
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
    groups: usize,
    ci: bool,
    dot_all: bool,
}

impl Parser<'_> {
    fn err<T>(&self, message: impl Into<String>) -> Result<T, PatternError> {
        Err(PatternError {
            offset: self.pos,
            message: message.into(),
        })
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn eat(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn flags(&mut self) -> Result<(), PatternError> {
        if !self.src.starts_with(b"(?") || self.src.get(2) == Some(&b':') {
            return Ok(());
        }
        self.pos = 2;
        loop {
            match self.peek() {
                Some(b'i') => self.ci = true,
                Some(b's') => self.dot_all = true,
                Some(b')') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return self.err("unknown flag; only (?i), (?s) and (?is) are supported"),
            }
            self.pos += 1;
        }
    }

    fn alt(&mut self, depth: usize) -> Result<Node, PatternError> {
        if depth > MAX_DEPTH {
            return self.err("groups nested too deeply");
        }
        let mut branches = vec![self.concat(depth)?];
        while self.eat(b'|') {
            branches.push(self.concat(depth)?);
        }
        Ok(if branches.len() == 1 {
            branches.pop().unwrap_or(Node::Empty)
        } else {
            Node::Alt(branches)
        })
    }

    fn concat(&mut self, depth: usize) -> Result<Node, PatternError> {
        let mut items = Vec::new();
        while let Some(b) = self.peek() {
            if b == b'|' || b == b')' {
                break;
            }
            let atom = self.atom(depth)?;
            let item = self.quantifier(atom)?;
            items.push(item);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(items),
        })
    }

    fn number(&mut self) -> Result<Option<u32>, PatternError> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if start == self.pos {
            return Ok(None);
        }
        let digits = std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("");
        match digits.parse::<u32>() {
            Ok(n) if n <= MAX_REPEAT => Ok(Some(n)),
            _ => self.err(format!("repetition count above {MAX_REPEAT}")),
        }
    }

    fn quantifier(&mut self, atom: Node) -> Result<Node, PatternError> {
        let (min, max) = match self.peek() {
            Some(b'*') => (0, None),
            Some(b'+') => (1, None),
            Some(b'?') => (0, Some(1)),
            Some(b'{') => {
                self.pos += 1;
                let Some(min) = self.number()? else {
                    return self.err("expected a number after `{`");
                };
                let max = if self.eat(b',') {
                    self.number()?
                } else {
                    Some(min)
                };
                if !self.eat(b'}') {
                    return self.err("expected `}`");
                }
                if max.is_some_and(|m| m < min) {
                    return self.err("repetition range is backwards");
                }
                self.pos -= 1; // re-consumed below
                (min, max)
            }
            _ => return Ok(atom),
        };
        self.pos += 1;
        if matches!(atom, Node::Bol | Node::Eol | Node::Empty) {
            return self.err("nothing to repeat");
        }
        let greedy = !self.eat(b'?');
        if matches!(self.peek(), Some(b'*' | b'+' | b'?' | b'{')) {
            return self.err("repeated quantifier; wrap the expression in a group first");
        }
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
            greedy,
        })
    }

    fn byte_set(&self, b: u8) -> ByteSet {
        let mut s = ByteSet::default();
        s.insert(b);
        if self.ci {
            s.fold_case();
        }
        s
    }

    fn atom(&mut self, depth: usize) -> Result<Node, PatternError> {
        let Some(b) = self.peek() else {
            return self.err("unexpected end of pattern");
        };
        self.pos += 1;
        Ok(match b {
            b'(' => {
                let index = if self.src[self.pos..].starts_with(b"?:") {
                    self.pos += 2;
                    None
                } else if self.peek() == Some(b'?') {
                    return self.err("only (?:...) groups and leading flags are supported");
                } else {
                    self.groups += 1;
                    if self.groups > MAX_GROUPS {
                        return self.err(format!("more than {MAX_GROUPS} capture groups"));
                    }
                    Some(self.groups)
                };
                let inner = self.alt(depth + 1)?;
                if !self.eat(b')') {
                    return self.err("unclosed group");
                }
                Node::Group(index, Box::new(inner))
            }
            b')' => return self.err("unmatched `)`"),
            b'[' => Node::Set(self.class()?),
            b'.' => {
                let mut s = ByteSet::default();
                s.negate();
                if !self.dot_all {
                    s.0[0] &= !(1 << b'\n');
                }
                Node::Set(s)
            }
            b'^' => Node::Bol,
            b'$' => Node::Eol,
            b'*' | b'+' | b'?' | b'{' => return self.err("nothing to repeat"),
            b'\\' => Node::Set(self.escape(false)?),
            _ => Node::Set(self.byte_set(b)),
        })
    }

    /// Parse the part after a backslash. Inside a class, `\b`-style
    /// shorthands still work and `-`/`]`/`^` may be escaped.
    fn escape(&mut self, in_class: bool) -> Result<ByteSet, PatternError> {
        let Some(b) = self.peek() else {
            return self.err("pattern ends with a backslash");
        };
        self.pos += 1;
        let mut set = match b {
            b'd' => ByteSet::digit(),
            b'w' => ByteSet::word(),
            b's' => ByteSet::space(),
            b'D' | b'W' | b'S' => {
                let mut s = match b {
                    b'D' => ByteSet::digit(),
                    b'W' => ByteSet::word(),
                    _ => ByteSet::space(),
                };
                s.negate();
                return Ok(s);
            }
            b'n' => self.byte_set(b'\n'),
            b'r' => self.byte_set(b'\r'),
            b't' => self.byte_set(b'\t'),
            b'0' => self.byte_set(0),
            b'x' => {
                let hex = |c: Option<u8>| c.and_then(|c| (c as char).to_digit(16));
                let (Some(hi), Some(lo)) =
                    (hex(self.peek()), hex(self.src.get(self.pos + 1).copied()))
                else {
                    return self.err("expected two hex digits after \\x");
                };
                self.pos += 2;
                // Hex escapes are exact bytes even with the `i` flag.
                let mut s = ByteSet::default();
                s.insert((hi * 16 + lo) as u8);
                return Ok(s);
            }
            _ if b.is_ascii_punctuation() || b == b' ' => self.byte_set(b),
            _ if in_class => return self.err("unknown escape in class"),
            _ => return self.err("unknown escape"),
        };
        if self.ci {
            set.fold_case();
        }
        Ok(set)
    }

    fn class(&mut self) -> Result<ByteSet, PatternError> {
        let negated = self.eat(b'^');
        let mut set = ByteSet::default();
        let mut first = true;
        loop {
            let Some(b) = self.peek() else {
                return self.err("unclosed `[`");
            };
            if b == b']' && !first {
                self.pos += 1;
                break;
            }
            first = false;
            self.pos += 1;
            let lo = if b == b'\\' {
                let s = self.escape(true)?;
                // A shorthand like \d can't start a range.
                match single(&s) {
                    Some(byte) if self.peek() == Some(b'-') => byte,
                    _ => {
                        set.union(&s);
                        continue;
                    }
                }
            } else {
                b
            };
            // A range, unless `-` is the last thing before `]`.
            if self.peek() == Some(b'-') && self.src.get(self.pos + 1).is_some_and(|&c| c != b']') {
                self.pos += 1;
                let hi = match self.peek() {
                    Some(b'\\') => {
                        self.pos += 1;
                        match single(&self.escape(true)?) {
                            Some(h) => h,
                            None => return self.err("class shorthand can't end a range"),
                        }
                    }
                    Some(h) => {
                        self.pos += 1;
                        h
                    }
                    None => return self.err("unclosed `[`"),
                };
                if hi < lo {
                    return self.err("class range is backwards");
                }
                set.insert_range(lo, hi);
            } else {
                set.insert(lo);
            }
        }
        if self.ci {
            set.fold_case();
        }
        if negated {
            set.negate();
        }
        Ok(set)
    }
}

/// The only byte in a set, ignoring case folding (lowest byte wins).
fn single(s: &ByteSet) -> Option<u8> {
    let count: u32 = s.0.iter().map(|w| w.count_ones()).sum();
    if count == 0 || count > 2 {
        return None;
    }
    (0..=255u8).find(|&b| s.contains(b))
}

#[derive(Debug, Clone)]
enum Inst {
    Set(ByteSet),
    Split(usize, usize),
    Jmp(usize),
    Save(usize),
    Bol,
    Eol,
    Match,
}

struct Compiler {
    prog: Vec<Inst>,
}

impl Compiler {
    fn push(&mut self, inst: Inst) -> Result<usize, PatternError> {
        if self.prog.len() >= MAX_PROGRAM {
            return Err(PatternError {
                offset: 0,
                message: "pattern is too large once repetitions are expanded".into(),
            });
        }
        self.prog.push(inst);
        Ok(self.prog.len() - 1)
    }

    fn patch(&mut self, at: usize, inst: Inst) {
        self.prog[at] = inst;
    }

    fn node(&mut self, n: &Node) -> Result<(), PatternError> {
        match n {
            Node::Empty => {}
            Node::Set(s) => {
                self.push(Inst::Set(*s))?;
            }
            Node::Bol => {
                self.push(Inst::Bol)?;
            }
            Node::Eol => {
                self.push(Inst::Eol)?;
            }
            Node::Group(Some(i), inner) => {
                self.push(Inst::Save(i * 2))?;
                self.node(inner)?;
                self.push(Inst::Save(i * 2 + 1))?;
            }
            Node::Group(None, inner) => self.node(inner)?,
            Node::Concat(items) => {
                for item in items {
                    self.node(item)?;
                }
            }
            Node::Alt(branches) => {
                let mut jumps = Vec::new();
                for (i, branch) in branches.iter().enumerate() {
                    if i + 1 < branches.len() {
                        let split = self.push(Inst::Split(0, 0))?;
                        self.node(branch)?;
                        jumps.push(self.push(Inst::Jmp(0))?);
                        let next = self.prog.len();
                        self.patch(split, Inst::Split(split + 1, next));
                    } else {
                        self.node(branch)?;
                    }
                }
                let end = self.prog.len();
                for j in jumps {
                    self.patch(j, Inst::Jmp(end));
                }
            }
            Node::Repeat {
                node,
                min,
                max,
                greedy,
            } => {
                for _ in 0..*min {
                    self.node(node)?;
                }
                match max {
                    None => {
                        // L: split body, end; body; jmp L
                        let split = self.push(Inst::Split(0, 0))?;
                        self.node(node)?;
                        self.push(Inst::Jmp(split))?;
                        let end = self.prog.len();
                        self.patch(split, self.choice(split + 1, end, *greedy));
                    }
                    Some(max) => {
                        let mut splits = Vec::new();
                        for _ in *min..*max {
                            splits.push(self.push(Inst::Split(0, 0))?);
                            self.node(node)?;
                        }
                        let end = self.prog.len();
                        for s in splits {
                            self.patch(s, self.choice(s + 1, end, *greedy));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn choice(&self, body: usize, skip: usize, greedy: bool) -> Inst {
        if greedy {
            Inst::Split(body, skip)
        } else {
            Inst::Split(skip, body)
        }
    }
}

/// A compiled pattern.
#[derive(Clone)]
pub struct Pattern {
    source: String,
    prog: Vec<Inst>,
    groups: usize,
    anchored: bool,
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Pattern").field(&self.source).finish()
    }
}

/// Byte ranges of each capture group; index 0 is the whole match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captures {
    slots: Vec<Option<usize>>,
}

impl Captures {
    /// The bytes captured by group `i`, if it took part in the match.
    pub fn get<'h>(&self, haystack: &'h [u8], i: usize) -> Option<&'h [u8]> {
        let start = (*self.slots.get(i * 2)?)?;
        let end = (*self.slots.get(i * 2 + 1)?)?;
        haystack.get(start..end)
    }
}

impl Pattern {
    pub fn new(source: &str) -> Result<Pattern, PatternError> {
        if source.len() > MAX_PATTERN_LEN {
            return Err(PatternError {
                offset: MAX_PATTERN_LEN,
                message: format!("pattern longer than {MAX_PATTERN_LEN} bytes"),
            });
        }
        let mut p = Parser {
            src: source.as_bytes(),
            pos: 0,
            groups: 0,
            ci: false,
            dot_all: false,
        };
        p.flags()?;
        let anchored = p.peek() == Some(b'^');
        let ast = p.alt(0)?;
        if p.pos != p.src.len() {
            return p.err("unmatched `)`");
        }
        let mut c = Compiler { prog: Vec::new() };
        c.push(Inst::Save(0))?;
        c.node(&ast)?;
        c.push(Inst::Save(1))?;
        c.push(Inst::Match)?;
        Ok(Pattern {
            source: source.to_string(),
            prog: c.prog,
            groups: p.groups,
            // `^a|b` isn't anchored as a whole; only treat a leading `^`
            // outside alternation as an anchor.
            anchored: anchored && !matches!(ast, Node::Alt(_)),
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// Number of capture groups (not counting the whole match).
    pub fn groups(&self) -> usize {
        self.groups
    }

    pub fn is_match(&self, haystack: &[u8]) -> bool {
        self.captures(haystack).is_some()
    }

    /// Find the leftmost match and its capture groups.
    pub fn captures(&self, haystack: &[u8]) -> Option<Captures> {
        let nslots = (self.groups + 1) * 2;
        let mut vm = Vm {
            prog: &self.prog,
            input: haystack,
            nslots,
            stack: Vec::new(),
        };
        let mut clist = Threads::new(self.prog.len(), nslots);
        let mut nlist = Threads::new(self.prog.len(), nslots);
        let mut scratch = vec![None; nslots];
        let mut matched: Option<Vec<Option<usize>>> = None;

        for at in 0..=haystack.len() {
            if matched.is_none() && (at == 0 || !self.anchored) {
                scratch.iter_mut().for_each(|s| *s = None);
                vm.add(&mut clist, 0, at, &mut scratch);
            }
            if clist.is_empty() {
                break;
            }
            for i in 0..clist.len() {
                let pc = clist.dense[i];
                match &self.prog[pc] {
                    Inst::Set(set) => {
                        if haystack.get(at).is_some_and(|&b| set.contains(b)) {
                            scratch.copy_from_slice(clist.caps(pc));
                            vm.add(&mut nlist, pc + 1, at + 1, &mut scratch);
                        }
                    }
                    Inst::Match => {
                        matched = Some(clist.caps(pc).to_vec());
                        // Lower-priority threads can't win any more.
                        break;
                    }
                    _ => {}
                }
            }
            std::mem::swap(&mut clist, &mut nlist);
            nlist.clear();
        }
        matched.map(|slots| Captures { slots })
    }
}

/// A sparse set of program counters, with each thread's capture slots.
struct Threads {
    dense: Vec<usize>,
    sparse: Vec<usize>,
    caps: Vec<Option<usize>>,
    nslots: usize,
}

impl Threads {
    fn new(size: usize, nslots: usize) -> Self {
        Threads {
            dense: Vec::with_capacity(size),
            sparse: vec![0; size],
            caps: vec![None; size * nslots],
            nslots,
        }
    }
    fn contains(&self, pc: usize) -> bool {
        let i = self.sparse[pc];
        i < self.dense.len() && self.dense[i] == pc
    }
    fn insert(&mut self, pc: usize) {
        self.sparse[pc] = self.dense.len();
        self.dense.push(pc);
    }
    fn len(&self) -> usize {
        self.dense.len()
    }
    fn is_empty(&self) -> bool {
        self.dense.is_empty()
    }
    fn clear(&mut self) {
        self.dense.clear();
    }
    fn caps(&self, pc: usize) -> &[Option<usize>] {
        &self.caps[pc * self.nslots..(pc + 1) * self.nslots]
    }
}

enum Frame {
    Explore(usize),
    Restore(usize, Option<usize>),
}

struct Vm<'a> {
    prog: &'a [Inst],
    input: &'a [u8],
    nslots: usize,
    stack: Vec<Frame>,
}

impl Vm<'_> {
    /// Add `pc` and everything reachable from it without consuming input,
    /// in priority order. `caps` is restored before returning.
    fn add(&mut self, list: &mut Threads, pc: usize, at: usize, caps: &mut [Option<usize>]) {
        self.stack.push(Frame::Explore(pc));
        while let Some(frame) = self.stack.pop() {
            let pc = match frame {
                Frame::Restore(slot, old) => {
                    caps[slot] = old;
                    continue;
                }
                Frame::Explore(pc) => pc,
            };
            if list.contains(pc) {
                continue;
            }
            list.insert(pc);
            match &self.prog[pc] {
                Inst::Jmp(x) => self.stack.push(Frame::Explore(*x)),
                Inst::Split(x, y) => {
                    self.stack.push(Frame::Explore(*y));
                    self.stack.push(Frame::Explore(*x));
                }
                Inst::Save(slot) => {
                    if *slot < self.nslots {
                        self.stack.push(Frame::Restore(*slot, caps[*slot]));
                        caps[*slot] = Some(at);
                    }
                    self.stack.push(Frame::Explore(pc + 1));
                }
                Inst::Bol => {
                    if at == 0 {
                        self.stack.push(Frame::Explore(pc + 1));
                    }
                }
                Inst::Eol => {
                    let rest = &self.input[at.min(self.input.len())..];
                    if rest.is_empty() || rest.starts_with(b"\n") || rest.starts_with(b"\r\n") {
                        self.stack.push(Frame::Explore(pc + 1));
                    }
                }
                Inst::Set(_) | Inst::Match => {
                    let n = self.nslots;
                    list.caps[pc * n..(pc + 1) * n].copy_from_slice(caps);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(p: &str, s: &[u8], i: usize) -> Option<String> {
        let pat = Pattern::new(p).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        let c = pat.captures(s)?;
        c.get(s, i).map(|b| String::from_utf8_lossy(b).into_owned())
    }

    fn whole(p: &str, s: &str) -> Option<String> {
        cap(p, s.as_bytes(), 0)
    }

    #[test]
    fn literals_and_search() {
        assert_eq!(whole("abc", "xxabcxx").as_deref(), Some("abc"));
        assert_eq!(whole("abd", "xxabcxx"), None);
        assert_eq!(whole("", "abc").as_deref(), Some(""));
    }

    #[test]
    fn anchors() {
        assert_eq!(whole("^abc", "abcdef").as_deref(), Some("abc"));
        assert_eq!(whole("^abc", "xabc"), None);
        assert_eq!(whole("abc$", "xabc\r\nmore").as_deref(), Some("abc"));
        assert_eq!(whole("abc$", "abcd"), None);
        assert_eq!(whole("^a|b", "xb").as_deref(), Some("b"));
    }

    #[test]
    fn classes_and_escapes() {
        assert_eq!(whole(r"[\d.]+", "v 1.24.0 x").as_deref(), Some("1.24.0"));
        assert_eq!(whole(r"[^\r\n]+", "ab\r\n").as_deref(), Some("ab"));
        assert_eq!(whole(r"[a-c-]+", "zz-ab-cz").as_deref(), Some("-ab-c"));
        assert_eq!(whole(r"[]a]+", "x]a]").as_deref(), Some("]a]"));
        assert_eq!(whole(r"\w+", "  foo_1 ").as_deref(), Some("foo_1"));
        assert_eq!(whole(r"\S+", "  a.b ").as_deref(), Some("a.b"));
        assert_eq!(cap(r"\x00\xff(.)", b"..\x00\xffZ", 1).as_deref(), Some("Z"));
        assert_eq!(whole(r"\(x\)", "a(x)b").as_deref(), Some("(x)"));
        assert_eq!(whole(r"[\x41-\x43]+", "zABCD").as_deref(), Some("ABC"));
    }

    #[test]
    fn dot_and_flags() {
        assert_eq!(whole("a.c", "a\nc"), None);
        assert_eq!(whole("(?s)a.c", "a\nc").as_deref(), Some("a\nc"));
        assert_eq!(
            whole("(?i)server: (\\w+)", "SERVER: X").as_deref(),
            Some("SERVER: X")
        );
        assert_eq!(whole("(?i)[a-c]+", "xAbCx").as_deref(), Some("AbC"));
        assert_eq!(whole("(?i)\\x41", "a"), None, "hex bytes are exact");
    }

    #[test]
    fn groups_and_alternation() {
        let s = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
        let p = r"^SSH-([\d.]+)-OpenSSH_([\w.]+)(?: (\S+))?";
        assert_eq!(cap(p, s, 1).as_deref(), Some("2.0"));
        assert_eq!(cap(p, s, 2).as_deref(), Some("8.9p1"));
        assert_eq!(cap(p, s, 3).as_deref(), Some("Ubuntu-3ubuntu0.6"));
        assert_eq!(cap("(a)|(b)", b"b", 1), None);
        assert_eq!(cap("(a)|(b)", b"b", 2).as_deref(), Some("b"));
        assert_eq!(whole("cat|category", "category").as_deref(), Some("cat"));
    }

    #[test]
    fn greedy_and_lazy() {
        assert_eq!(cap("<(.*)>", b"<a><b>", 1).as_deref(), Some("a><b"));
        assert_eq!(cap("<(.*?)>", b"<a><b>", 1).as_deref(), Some("a"));
        assert_eq!(cap("(a+?)", b"aaa", 1).as_deref(), Some("a"));
        assert_eq!(cap("(a??)a", b"aa", 1).as_deref(), Some(""));
    }

    #[test]
    fn counted_repetition() {
        assert_eq!(whole(r"\d{3}", "12 345").as_deref(), Some("345"));
        assert_eq!(whole(r"^\d{2,}", "12345x").as_deref(), Some("12345"));
        assert_eq!(whole(r"^\d{1,2}", "12345").as_deref(), Some("12"));
        assert_eq!(
            whole(r"^[\s\S]{3}X", "\x00\n\x01X").as_deref(),
            Some("\x00\n\x01X")
        );
    }

    #[test]
    fn empty_loops_terminate() {
        assert_eq!(whole("(a*)*b", "aaab").as_deref(), Some("aaab"));
        assert_eq!(whole("(a?)*?$", "aa").as_deref(), Some("aa"));
        assert!(Pattern::new("(|a)+").unwrap().is_match(b"zzz"));
    }

    #[test]
    fn pathological_patterns_stay_fast() {
        // (a+)+b against a long run of `a`s takes forever with backtracking.
        let p = Pattern::new("(a+)+b").unwrap();
        let input = vec![b'a'; 20_000];
        let started = std::time::Instant::now();
        assert!(!p.is_match(&input));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn rejects_bad_patterns() {
        for bad in [
            "(",
            ")",
            "a)",
            "[a",
            "[z-a]",
            "*a",
            "a**",
            "\\",
            "\\q",
            "\\x4",
            "(?x)",
            "(?=a)",
            "a{2,1}",
            "a{999}",
            "a{",
            "a{x}",
            "^*",
            "(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)",
        ] {
            assert!(Pattern::new(bad).is_err(), "{bad:?} should be rejected");
        }
        let deep = "(".repeat(100) + &")".repeat(100);
        assert!(Pattern::new(&deep).is_err());
        assert!(
            Pattern::new(&"a{255}".repeat(200)).is_err(),
            "program size cap"
        );
    }
}
