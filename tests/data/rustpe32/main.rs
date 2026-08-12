//! A small freestanding Rust program used only as a parser fixture.
//!
//! It exists to exercise three things at once on i686: rust-lld's public
//! records, procedure records from rustc-compiled code, and inline sites --
//! `hash_round` and `mix_pair` are `#[inline(always)]` and called from several
//! places, so the PDB records them as S_INLINESITE rather than as procedures.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

extern "C" {
    // Defined in stubs.s. Hand-written assembly declares no COFF function
    // type, so these arrive as publics with PUBLIC_FLAG_FUNCTION clear and
    // no procedure record behind them.
    fn platform_seed() -> u32;
    fn platform_report(value: u32);
}

#[inline(always)]
fn hash_round(acc: u32, x: u32) -> u32 {
    acc.wrapping_mul(2654435761).rotate_left(7) ^ x
}

#[inline(always)]
fn mix_pair(a: u32, b: u32) -> u32 {
    hash_round(hash_round(a, b), b.rotate_right(3))
}

#[no_mangle]
pub extern "C" fn checksum(data: *const u8, len: usize) -> u32 {
    let mut acc: u32 = 0x811C9DC5;
    let mut i = 0usize;
    while i < len {
        let byte = unsafe { *data.add(i) } as u32;
        acc = hash_round(acc, byte);
        i += 1;
    }
    acc
}

#[no_mangle]
pub extern "C" fn combine(a: u32, b: u32) -> u32 {
    mix_pair(a, b)
}

#[no_mangle]
pub extern "C" fn spread(seed: u32, rounds: u32) -> u32 {
    let mut acc = seed;
    let mut i = 0u32;
    while i < rounds {
        acc = mix_pair(acc, i);
        i = i.wrapping_add(1);
    }
    acc
}

#[inline(never)]
fn digest(seed: u32) -> u32 {
    let table = [1u8, 2, 3, 5, 8, 13, 21, 34];
    combine(checksum(table.as_ptr(), table.len()), spread(seed, 11))
}

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> u32 {
    let seed = unsafe { platform_seed() };
    let result = digest(seed);
    unsafe { platform_report(result) };
    result
}
