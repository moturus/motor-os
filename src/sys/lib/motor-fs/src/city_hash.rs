// Copyright (c) 2011 Google, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// CityHash, by Geoff Pike and Jyrki Alakuijala
//
// This file provides CityHash64() and related functions.
//
// Ported to Rust from the original C++ implementation.
//
// Copied from https://github.com/cmackenzie1/simplehash/blob/main/src/city.rs
// which is MIT licensed.

#![allow(dead_code)]

use std::cmp::min;

fn unaligned_load64(p: &[u8]) -> u64 {
    let mut result: u64 = 0;
    let bytes = min(p.len(), 8);
    for (i, &byte) in p.iter().take(bytes).enumerate() {
        result |= (byte as u64) << (i * 8);
    }
    result
}

fn unaligned_load32(p: &[u8]) -> u32 {
    let mut result: u32 = 0;
    let bytes = min(p.len(), 4);
    for (i, &byte) in p.iter().take(bytes).enumerate() {
        result |= (byte as u32) << (i * 8);
    }
    result
}

// Check endianness at runtime
fn is_big_endian() -> bool {
    let n: u16 = 1;
    // Safe because we only inspect the bytes, not interpret them as a reference
    let bytes: [u8; 2] = n.to_ne_bytes();
    bytes[0] == 0
}

fn uint32_in_expected_order(x: u32) -> u32 {
    if is_big_endian() { x.swap_bytes() } else { x }
}

fn uint64_in_expected_order(x: u64) -> u64 {
    if is_big_endian() { x.swap_bytes() } else { x }
}

fn fetch64(p: &[u8]) -> u64 {
    uint64_in_expected_order(unaligned_load64(p))
}

fn fetch32(p: &[u8]) -> u32 {
    uint32_in_expected_order(unaligned_load32(p))
}

// Some primes between 2^63 and 2^64 for various uses.
const K0: u64 = 0xc3a5c85c97cb3127;
const K1: u64 = 0xb492b66fbe98f273;
const K2: u64 = 0x9ae16a3b2f90404f;

// Magic numbers for 32-bit hashing. Copied from Murmur3.
const C1: u32 = 0xcc9e2d51;
const C2: u32 = 0x1b873593;

// A 32-bit to 32-bit integer hash copied from Murmur3.
fn fmix(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h
}

fn rotate32(val: u32, shift: i32) -> u32 {
    // Avoid shifting by 32: doing so yields an undefined result.
    if shift == 0 {
        val
    } else {
        (val >> shift) | (val << (32 - shift))
    }
}

fn permute3(a: &mut u32, b: &mut u32, c: &mut u32) {
    let temp = *a;
    *a = *b;
    *b = *c;
    *c = temp;
}

fn mur(a: u32, h: u32) -> u32 {
    // Helper from Murmur3 for combining two 32-bit values.
    let mut a = a.wrapping_mul(C1);
    a = rotate32(a, 17);
    a = a.wrapping_mul(C2);
    let mut h = h ^ a;
    h = rotate32(h, 19);
    h.wrapping_mul(5).wrapping_add(0xe6546b64)
}

fn hash32_len13to24(s: &[u8], len: usize) -> u32 {
    let a = fetch32(&s[(len >> 1) - 4..]);
    let b = fetch32(&s[4..]);
    let c = fetch32(&s[len - 8..]);
    let d = fetch32(&s[len >> 1..]);
    let e = fetch32(s);
    let f = fetch32(&s[len - 4..]);
    let h = len as u32;

    fmix(mur(f, mur(e, mur(d, mur(c, mur(b, mur(a, h)))))))
}

fn hash32_len0to4(s: &[u8], len: usize) -> u32 {
    let mut b: u32 = 0;
    let mut c: u32 = 9;
    for &byte in s.iter().take(len) {
        let v = byte as i8;
        b = b.wrapping_mul(C1).wrapping_add(v as u32);
        c ^= b;
    }
    fmix(mur(b, mur(len as u32, c)))
}

fn hash32_len5to12(s: &[u8], len: usize) -> u32 {
    let mut a = len as u32;
    let mut b = a.wrapping_mul(5);
    let mut c: u32 = 9;
    let d = b;

    a = a.wrapping_add(fetch32(s));
    b = b.wrapping_add(fetch32(&s[len - 4..]));
    c = c.wrapping_add(fetch32(&s[((len >> 1) & 4)..]));

    fmix(mur(c, mur(b, mur(a, d))))
}

pub fn city_hash32(s: &[u8]) -> u32 {
    let len = s.len();
    if len <= 24 {
        if len <= 12 {
            if len <= 4 {
                return hash32_len0to4(s, len);
            } else {
                return hash32_len5to12(s, len);
            }
        } else {
            return hash32_len13to24(s, len);
        }
    }

    // len > 24
    let mut h = len as u32;
    let mut g = C1.wrapping_mul(h);
    let mut f = g;

    let a0 = rotate32(fetch32(&s[len - 4..]).wrapping_mul(C1), 17).wrapping_mul(C2);
    let a1 = rotate32(fetch32(&s[len - 8..]).wrapping_mul(C1), 17).wrapping_mul(C2);
    let a2 = rotate32(fetch32(&s[len - 16..]).wrapping_mul(C1), 17).wrapping_mul(C2);
    let a3 = rotate32(fetch32(&s[len - 12..]).wrapping_mul(C1), 17).wrapping_mul(C2);
    let a4 = rotate32(fetch32(&s[len - 20..]).wrapping_mul(C1), 17).wrapping_mul(C2);

    h ^= a0;
    h = rotate32(h, 19);
    h = h.wrapping_mul(5).wrapping_add(0xe6546b64);
    h ^= a2;
    h = rotate32(h, 19);
    h = h.wrapping_mul(5).wrapping_add(0xe6546b64);
    g ^= a1;
    g = rotate32(g, 19);
    g = g.wrapping_mul(5).wrapping_add(0xe6546b64);
    g ^= a3;
    g = rotate32(g, 19);
    g = g.wrapping_mul(5).wrapping_add(0xe6546b64);
    f = f.wrapping_add(a4);
    f = rotate32(f, 19);
    f = f.wrapping_mul(5).wrapping_add(0xe6546b64);

    let mut iters = (len - 1) / 20;
    let mut s_pos = 0;

    loop {
        let a0 = rotate32(fetch32(&s[s_pos..]).wrapping_mul(C1), 17).wrapping_mul(C2);
        let a1 = fetch32(&s[s_pos + 4..]);
        let a2 = rotate32(fetch32(&s[s_pos + 8..]).wrapping_mul(C1), 17).wrapping_mul(C2);
        let a3 = rotate32(fetch32(&s[s_pos + 12..]).wrapping_mul(C1), 17).wrapping_mul(C2);
        let a4 = fetch32(&s[s_pos + 16..]);

        h ^= a0;
        h = rotate32(h, 18);
        h = h.wrapping_mul(5).wrapping_add(0xe6546b64);
        f = f.wrapping_add(a1);
        f = rotate32(f, 19);
        f = f.wrapping_mul(C1);
        g = g.wrapping_add(a2);
        g = rotate32(g, 18);
        g = g.wrapping_mul(5).wrapping_add(0xe6546b64);
        h ^= a3.wrapping_add(a1);
        h = rotate32(h, 19);
        h = h.wrapping_mul(5).wrapping_add(0xe6546b64);
        g ^= a4;
        g = g.swap_bytes().wrapping_mul(5);
        h = h.wrapping_add(a4.wrapping_mul(5));
        h = h.swap_bytes();
        f = f.wrapping_add(a0);

        let mut f_tmp = f;
        let mut h_tmp = h;
        let mut g_tmp = g;
        permute3(&mut f_tmp, &mut h_tmp, &mut g_tmp);
        f = f_tmp;
        h = h_tmp;
        g = g_tmp;

        s_pos += 20;
        iters -= 1;
        if iters == 0 {
            break;
        }
    }

    g = rotate32(g, 11).wrapping_mul(C1);
    g = rotate32(g, 17).wrapping_mul(C1);
    f = rotate32(f, 11).wrapping_mul(C1);
    f = rotate32(f, 17).wrapping_mul(C1);
    h = rotate32(h.wrapping_add(g), 19);
    h = h.wrapping_mul(5).wrapping_add(0xe6546b64);
    h = rotate32(h, 17).wrapping_mul(C1);
    h = rotate32(h.wrapping_add(f), 19);
    h = h.wrapping_mul(5).wrapping_add(0xe6546b64);
    h = rotate32(h, 17).wrapping_mul(C1);
    h
}

// Bitwise right rotate.
fn rotate(val: u64, shift: i32) -> u64 {
    // Avoid shifting by 64: doing so yields an undefined result.
    if shift == 0 {
        val
    } else {
        (val >> shift) | (val << (64 - shift))
    }
}

fn shift_mix(val: u64) -> u64 {
    val ^ (val >> 47)
}

fn hash128_to_64(x: u128) -> u64 {
    let low = x as u64;
    let high = (x >> 64) as u64;
    // Murmur-inspired hashing.
    const MUL: u64 = 0x9ddfea08eb382d69;
    let mut a = (low ^ high).wrapping_mul(MUL);
    a ^= a >> 47;
    let mut b = (high ^ a).wrapping_mul(MUL);
    b ^= b >> 47;
    b = b.wrapping_mul(MUL);
    b
}

fn hash_len16(u: u64, v: u64) -> u64 {
    hash128_to_64((u as u128) ^ ((v as u128) << 64))
}

fn hash_len16_mul(u: u64, v: u64, mul: u64) -> u64 {
    // Murmur-inspired hashing.
    let mut a = (u ^ v).wrapping_mul(mul);
    a ^= a >> 47;
    let mut b = (v ^ a).wrapping_mul(mul);
    b ^= b >> 47;
    b = b.wrapping_mul(mul);
    b
}

fn hash_len0to16(s: &[u8]) -> u64 {
    let len = s.len();
    if len >= 8 {
        let mul = K2.wrapping_add((len as u64).wrapping_mul(2));
        let a = fetch64(s).wrapping_add(K2);
        let b = fetch64(&s[len - 8..]);
        let c = rotate(b, 37).wrapping_mul(mul).wrapping_add(a);
        let d = (rotate(a, 25).wrapping_add(b)).wrapping_mul(mul);
        hash_len16_mul(c, d, mul)
    } else if len >= 4 {
        let mul = K2.wrapping_add((len as u64).wrapping_mul(2));
        let a = fetch32(s) as u64;
        hash_len16_mul(
            (len as u64).wrapping_add(a << 3),
            fetch32(&s[len - 4..]) as u64,
            mul,
        )
    } else if len > 0 {
        let a = s[0];
        let b = s[len >> 1];
        let c = s[len - 1];
        let y = (a as u32).wrapping_add((b as u32) << 8);
        let z = (len as u32).wrapping_add((c as u32) << 2);
        shift_mix((y as u64).wrapping_mul(K2) ^ (z as u64).wrapping_mul(K0)).wrapping_mul(K2)
    } else {
        K2
    }
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
fn hash_len17to32(s: &[u8]) -> u64 {
    let len = s.len();
    let mul = K2.wrapping_add((len as u64).wrapping_mul(2));
    let a = fetch64(s).wrapping_mul(K1);
    let b = fetch64(&s[8..]);
    let c = fetch64(&s[len - 8..]).wrapping_mul(mul);
    let d = fetch64(&s[len - 16..]).wrapping_mul(K2);

    hash_len16_mul(
        rotate(a.wrapping_add(b), 43)
            .wrapping_add(rotate(c, 30))
            .wrapping_add(d),
        a.wrapping_add(rotate(b.wrapping_add(K2), 18))
            .wrapping_add(c),
        mul,
    )
}

// Return a 16-byte hash for 48 bytes. Quick and dirty.
// Callers do best to use "random-looking" values for a and b.
fn weak_hash_len32_with_seeds(
    w: u64,
    x: u64,
    y: u64,
    z: u64,
    mut a: u64,
    mut b: u64,
) -> (u64, u64) {
    a = a.wrapping_add(w);
    b = rotate(b.wrapping_add(a).wrapping_add(z), 21);
    let c = a;
    a = a.wrapping_add(x);
    a = a.wrapping_add(y);
    b = b.wrapping_add(rotate(a, 44));
    (a.wrapping_add(z), b.wrapping_add(c))
}

// Return a 16-byte hash for s[0] ... s[31], a, and b. Quick and dirty.
fn weak_hash_len32_with_seeds_bytes(s: &[u8], a: u64, b: u64) -> (u64, u64) {
    weak_hash_len32_with_seeds(
        fetch64(s),
        fetch64(&s[8..]),
        fetch64(&s[16..]),
        fetch64(&s[24..]),
        a,
        b,
    )
}

// Return an 8-byte hash for 33 to 64 bytes.
fn hash_len33to64(s: &[u8]) -> u64 {
    let len = s.len();
    let mul = K2.wrapping_add((len as u64).wrapping_mul(2));
    let a = fetch64(s).wrapping_mul(K2);
    let b = fetch64(&s[8..]);
    let c = fetch64(&s[len - 24..]);
    let d = fetch64(&s[len - 32..]);
    let e = fetch64(&s[16..]).wrapping_mul(K2);
    let f = fetch64(&s[24..]).wrapping_mul(9);
    let g = fetch64(&s[len - 8..]);
    let h = fetch64(&s[len - 16..]).wrapping_mul(mul);

    let u =
        rotate(a.wrapping_add(g), 43).wrapping_add((rotate(b, 30).wrapping_add(c)).wrapping_mul(9));
    let v = ((a.wrapping_add(g)) ^ d).wrapping_add(f).wrapping_add(1);
    let w = ((u.wrapping_add(v)).wrapping_mul(mul))
        .swap_bytes()
        .wrapping_add(h);
    let x = rotate(e.wrapping_add(f), 42).wrapping_add(c);
    let y = ((v.wrapping_add(w)).wrapping_mul(mul))
        .swap_bytes()
        .wrapping_add(g)
        .wrapping_mul(mul);
    let z = e.wrapping_add(f).wrapping_add(c);

    let a = ((x.wrapping_add(z)).wrapping_mul(mul).wrapping_add(y))
        .swap_bytes()
        .wrapping_add(b);
    let b = shift_mix(
        (z.wrapping_add(a))
            .wrapping_mul(mul)
            .wrapping_add(d)
            .wrapping_add(h),
    )
    .wrapping_mul(mul);

    b.wrapping_add(x)
}

pub fn city_hash64(s: &[u8]) -> u64 {
    let len = s.len();
    if len <= 32 {
        if len <= 16 {
            return hash_len0to16(s);
        } else {
            return hash_len17to32(s);
        }
    } else if len <= 64 {
        return hash_len33to64(s);
    }

    // For strings over 64 bytes we hash the end first, and then as we
    // loop we keep 56 bytes of state: v, w, x, y, and z.
    let mut x = fetch64(&s[len - 40..]);
    let mut y = fetch64(&s[len - 16..]).wrapping_add(fetch64(&s[len - 56..]));
    let mut z = hash_len16(
        fetch64(&s[len - 48..]).wrapping_add(len as u64),
        fetch64(&s[len - 24..]),
    );

    let mut v = weak_hash_len32_with_seeds_bytes(&s[len - 64..], len as u64, z);
    let mut w = weak_hash_len32_with_seeds_bytes(&s[len - 32..], y.wrapping_add(K1), x);

    x = x.wrapping_mul(K1).wrapping_add(fetch64(s));

    // Process 64-byte chunks
    let mut s_pos = 0;
    let mut remaining_len = (len - 1) & !63;

    loop {
        x = rotate(
            x.wrapping_add(y)
                .wrapping_add(v.0)
                .wrapping_add(fetch64(&s[s_pos + 8..])),
            37,
        )
        .wrapping_mul(K1);

        y = rotate(
            y.wrapping_add(v.1).wrapping_add(fetch64(&s[s_pos + 48..])),
            42,
        )
        .wrapping_mul(K1);

        x ^= w.1;
        y = y.wrapping_add(v.0).wrapping_add(fetch64(&s[s_pos + 40..]));
        z = rotate(z.wrapping_add(w.0), 33).wrapping_mul(K1);

        v = weak_hash_len32_with_seeds_bytes(
            &s[s_pos..],
            v.1.wrapping_mul(K1),
            x.wrapping_add(w.0),
        );
        w = weak_hash_len32_with_seeds_bytes(
            &s[s_pos + 32..],
            z.wrapping_add(w.1),
            y.wrapping_add(fetch64(&s[s_pos + 16..])),
        );

        std::mem::swap(&mut z, &mut x);

        s_pos += 64;
        remaining_len -= 64;
        if remaining_len == 0 {
            break;
        }
    }

    hash_len16(
        hash_len16(v.0, w.0)
            .wrapping_add(shift_mix(y).wrapping_mul(K1))
            .wrapping_add(z),
        hash_len16(v.1, w.1).wrapping_add(x),
    )
}

pub fn city_hash64_with_seed(s: &[u8], seed: u64) -> u64 {
    city_hash64_with_seeds(s, K2, seed)
}

pub fn city_hash64_with_seeds(s: &[u8], seed0: u64, seed1: u64) -> u64 {
    hash_len16(city_hash64(s).wrapping_sub(seed0), seed1)
}

// A subroutine for CityHash128(). Returns a decent 128-bit hash for strings
// of any length representable in signed long. Based on City and Murmur.
fn city_murmur(s: &[u8], seed: u128) -> u128 {
    let len = s.len();
    let mut a: u64 = (seed & 0xffffffffffffffff) as u64; // low 64 bits
    let mut b: u64 = ((seed >> 64) & 0xffffffffffffffff) as u64; // high 64 bits
    let mut c: u64;
    let mut d: u64;

    if len <= 16 {
        a = shift_mix(a.wrapping_mul(K1)).wrapping_mul(K1);
        c = b.wrapping_mul(K1).wrapping_add(hash_len0to16(s));
        d = shift_mix(a.wrapping_add(if len >= 8 { fetch64(s) } else { c }));
    } else {
        c = hash_len16(fetch64(&s[len - 8..]).wrapping_add(K1), a);
        d = hash_len16(
            b.wrapping_add(len as u64),
            c.wrapping_add(fetch64(&s[len - 16..])),
        );
        a = a.wrapping_add(d);

        let mut s_pos = 0;
        let len_aligned = (len / 16) * 16;
        while s_pos < len_aligned {
            a ^= shift_mix(fetch64(&s[s_pos..]).wrapping_mul(K1)).wrapping_mul(K1);
            a = a.wrapping_mul(K1);
            b ^= a;
            c ^= shift_mix(fetch64(&s[s_pos + 8..]).wrapping_mul(K1)).wrapping_mul(K1);
            c = c.wrapping_mul(K1);
            d ^= c;
            s_pos += 16;
        }
    }

    a = hash_len16(a, c);
    b = hash_len16(d, b);

    (a as u128) ^ ((b as u128) << 64)
}

pub fn city_hash128_with_seed(s: &[u8], seed: u128) -> u128 {
    let len = s.len();
    if len < 128 {
        return city_murmur(s, seed);
    }

    // We expect len >= 128 to be the common case. Keep 56 bytes of state:
    // v, w, x, y, and z.
    let mut v = (0, 0);
    let mut w = (0, 0);
    let mut x = (seed & 0xffffffffffffffff) as u64; // low 64 bits
    let mut y = ((seed >> 64) & 0xffffffffffffffff) as u64; // high 64 bits
    let mut z = (len as u64).wrapping_mul(K1);

    v.0 = rotate(y.wrapping_add(K1), 49)
        .wrapping_mul(K1)
        .wrapping_add(fetch64(s));
    v.1 = rotate(v.0, 42)
        .wrapping_mul(K1)
        .wrapping_add(fetch64(&s[8..]));
    w.0 = rotate(y.wrapping_add(z), 35)
        .wrapping_mul(K1)
        .wrapping_add(x);
    w.1 = rotate(x.wrapping_add(fetch64(&s[88..])), 53).wrapping_mul(K1);

    // This is the same inner loop as CityHash64(), manually unrolled.
    let mut s_pos = 0;
    let len_aligned = (len / 128) * 128;

    // Process 128-byte chunks
    while s_pos < len_aligned {
        x = rotate(
            x.wrapping_add(y)
                .wrapping_add(v.0)
                .wrapping_add(fetch64(&s[s_pos + 8..])),
            37,
        )
        .wrapping_mul(K1);

        y = rotate(
            y.wrapping_add(v.1).wrapping_add(fetch64(&s[s_pos + 48..])),
            42,
        )
        .wrapping_mul(K1);

        x ^= w.1;
        y = y.wrapping_add(v.0).wrapping_add(fetch64(&s[s_pos + 40..]));
        z = rotate(z.wrapping_add(w.0), 33).wrapping_mul(K1);

        v = weak_hash_len32_with_seeds_bytes(
            &s[s_pos..],
            v.1.wrapping_mul(K1),
            x.wrapping_add(w.0),
        );

        w = weak_hash_len32_with_seeds_bytes(
            &s[s_pos + 32..],
            z.wrapping_add(w.1),
            y.wrapping_add(fetch64(&s[s_pos + 16..])),
        );

        std::mem::swap(&mut z, &mut x);
        s_pos += 64;

        x = rotate(
            x.wrapping_add(y)
                .wrapping_add(v.0)
                .wrapping_add(fetch64(&s[s_pos + 8..])),
            37,
        )
        .wrapping_mul(K1);

        y = rotate(
            y.wrapping_add(v.1).wrapping_add(fetch64(&s[s_pos + 48..])),
            42,
        )
        .wrapping_mul(K1);

        x ^= w.1;
        y = y.wrapping_add(v.0).wrapping_add(fetch64(&s[s_pos + 40..]));
        z = rotate(z.wrapping_add(w.0), 33).wrapping_mul(K1);

        v = weak_hash_len32_with_seeds_bytes(
            &s[s_pos..],
            v.1.wrapping_mul(K1),
            x.wrapping_add(w.0),
        );

        w = weak_hash_len32_with_seeds_bytes(
            &s[s_pos + 32..],
            z.wrapping_add(w.1),
            y.wrapping_add(fetch64(&s[s_pos + 16..])),
        );

        std::mem::swap(&mut z, &mut x);
        s_pos += 64;
    }

    let len_remaining = len - s_pos;

    x = x.wrapping_add(rotate(v.0.wrapping_add(z), 49).wrapping_mul(K0));
    y = y.wrapping_mul(K0).wrapping_add(rotate(w.1, 37));
    z = z.wrapping_mul(K0).wrapping_add(rotate(w.0, 27));
    w.0 = w.0.wrapping_mul(9);
    v.0 = v.0.wrapping_mul(K0);

    // If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
    let mut tail_done = 0;
    while tail_done < len_remaining {
        tail_done += 32;
        y = rotate(x.wrapping_add(y), 42)
            .wrapping_mul(K0)
            .wrapping_add(v.1);
        w.0 =
            w.0.wrapping_add(fetch64(&s[s_pos + len_remaining - tail_done + 16..]));
        x = x.wrapping_mul(K0).wrapping_add(w.0);
        z = z
            .wrapping_add(w.1)
            .wrapping_add(fetch64(&s[s_pos + len_remaining - tail_done..]));
        w.1 = w.1.wrapping_add(v.0);
        v = weak_hash_len32_with_seeds_bytes(
            &s[s_pos + len_remaining - tail_done..],
            v.0.wrapping_add(z),
            v.1,
        );
        v.0 = v.0.wrapping_mul(K0);
    }

    // At this point our 56 bytes of state should contain more than
    // enough information for a strong 128-bit hash. We use two
    // different 56-byte-to-8-byte hashes to get a 16-byte final result.
    x = hash_len16(x, v.0);
    y = hash_len16(y.wrapping_add(z), w.0);

    (hash_len16(x.wrapping_add(v.1), w.1).wrapping_add(y) as u128)
        ^ ((hash_len16(x.wrapping_add(w.1), y.wrapping_add(v.1)) as u128) << 64)
}

pub fn city_hash128(s: &[u8]) -> u128 {
    let len = s.len();
    if len >= 16 {
        let seed = (fetch64(s) as u128) ^ ((fetch64(&s[8..]) as u128) << 64);
        let remaining = &s[16..];
        city_hash128_with_seed(remaining, seed)
    } else {
        city_hash128_with_seed(s, (K0 as u128) ^ ((K1 as u128) << 64))
    }
}

pub struct CityHasher64 {
    buffer: Vec<u8>,
    seed: u64,
}

impl Default for CityHasher64 {
    fn default() -> Self {
        Self::new()
    }
}

impl CityHasher64 {
    pub fn new() -> Self {
        CityHasher64 {
            buffer: Vec::new(),
            seed: 0,
        }
    }

    pub fn with_seed(seed: u64) -> Self {
        CityHasher64 {
            buffer: Vec::new(),
            seed,
        }
    }
}

impl std::hash::Hasher for CityHasher64 {
    fn write(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    fn finish(&self) -> u64 {
        city_hash64(&self.buffer)
    }
}

impl std::hash::BuildHasher for CityHasher64 {
    type Hasher = CityHasher64;

    fn build_hasher(&self) -> Self::Hasher {
        CityHasher64::new()
    }
}

type CityHashHasherDefault = std::hash::BuildHasherDefault<CityHasher64>;

#[test]
fn test_vectors() {
    assert_eq!(0x9ae16a3b2f90404f, city_hash64(&[]));
    assert_eq!(0xb3454265b6df75e3, city_hash64(b"a"));
    assert_eq!(0x24a5b3a074e7f369, city_hash64(b"abc"));
    assert_eq!(0x45bcb7e9138697be, city_hash64(b"foo bar baz"));
}
