// Minimal fixture for SMDA PE symbol recovery (smda#229 / smda#230).
// Deliberately small, but with enough distinct, non-inlined functions to make
// symbol recovery measurable, and a panic path so MSVC emits EH funclets --
// which is what produces the sub-function .pdata entries in #230.

#[inline(never)]
pub fn tally(words: &[&str]) -> usize {
    let mut n = 0usize;
    for w in words { n = n.wrapping_add(w.len()); }
    n
}

#[inline(never)]
pub fn risky(v: &[u8], i: usize) -> u8 {
    let boxed: Vec<u8> = v.to_vec();   // droppable held across a fallible call
    boxed[i]                            // may panic -> cleanup funclet
}

#[inline(never)]
pub fn describe(n: usize) -> String {
    format!("n={n} parity={}", if n % 2 == 0 { "even" } else { "odd" })
}

fn main() {
    let words = ["alpha", "beta", "gamma"];
    let n = tally(&words);
    println!("{} {} {}", n, describe(n), risky(b"abc", n % 3));
}
