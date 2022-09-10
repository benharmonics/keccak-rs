//! Implementation originally by Gilles Van Assche, hereby denoted as "the implementer".
//!
//! This Rust implementation was based on the Python version of the algorithm(s):
//!
//! <https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py>
//!
//! For more information, feedback or questions, please refer to the website:
//! <https://keccak.team/>
//!
//! To the extent possible under law, the implementer has waived all copyright
//! and related or neighboring rights to the source code in this file.
//! <http://creativecommons.org/publicdomain/zero/1.0/>
use std::cmp::min;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

fn rol64(a: u64, n: u64) -> u64 {
  let a = a as u128;
  let n = n as u128;
  let res = ((a >> (64 - (n % 64))) + (a << (n % 64))) % (1 << 64);
  res.try_into().expect("Error in `rol64` logic") // can't fail
}

fn load64(state: &[u8]) -> Result<u64, &'static str> {
  if state.len() != 8 {
    return Err("State vector must be length 8");
  }
  let mut res = 0;
  for (i, s) in state.iter().enumerate() {
    res += (*s as u64) << (8 * i)
  }

  Ok(res)
}

fn store64(a: u64) -> Vec<u8> {
  let mut v = Vec::with_capacity(8);
  for i in 0..8 {
    v.push((((a) >> (8 * i)) % 256) as u8)
  }

  v
}

/// Possible errors in Keccak hashing function
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HashError {
  Capacity,
  Rate,
}

impl Display for HashError {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    match self {
      Self::Capacity => write!(f, "Required: rate + capacity = 1600"),
      Self::Rate => write!(f, "Required: rate ≡ 0 (mod 8)"),
    }
  }
}

impl Error for HashError {}

fn keccak_f1600_on_lanes(lanes: &mut [u64]) {
  let mut r = 1;
  for _ in 0..24 {
    // θ
    let c = vec![
      lanes[0] ^ lanes[1] ^ lanes[2] ^ lanes[3] ^ lanes[4],
      lanes[5] ^ lanes[6] ^ lanes[7] ^ lanes[8] ^ lanes[9],
      lanes[10] ^ lanes[11] ^ lanes[12] ^ lanes[13] ^ lanes[14],
      lanes[15] ^ lanes[16] ^ lanes[17] ^ lanes[18] ^ lanes[19],
      lanes[20] ^ lanes[21] ^ lanes[22] ^ lanes[23] ^ lanes[24],
    ];
    // Yeah, most of these modulos don't do anything. But the cost is low and
    // it's explicitly 1:1 with the original implementation.
    // Ignore the clippy warning.
    let d = vec![
      c[4 % 5] ^ rol64(c[1 % 5], 1),
      c[5 % 5] ^ rol64(c[2 % 5], 1),
      c[6 % 5] ^ rol64(c[3 % 5], 1),
      c[7 % 5] ^ rol64(c[4 % 5], 1),
      c[8 % 5] ^ rol64(c[5 % 5], 1),
    ];
    for x in 0..5 {
      for y in 0..5 {
        lanes[y + 5 * x] ^= d[x];
      }
    }
    // ρ and π
    let (mut x, mut y) = (1, 0);
    let mut curr = lanes[5 * x];
    for t in 0..24 {
      (x, y) = (y, (2 * x + 3 * y) % 5);
      (curr, lanes[y + 5 * x]) = (lanes[y + 5 * x], rol64(curr, (t + 1) * (t + 2) / 2));
    }
    // χ
    for y in 0..5 {
      let mut t = Vec::with_capacity(5);
      for x in 0..5 {
        t.push(lanes[y + 5 * x]);
      }
      for x in 0..5 {
        lanes[y + 5 * x] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
      }
    }
    // ι
    for j in 0..7 {
      r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256;
      if r & 2 != 0 {
        lanes[0] ^= 1 << ((1 << j) - 1);
      }
    }
  }
}

fn keccak_f1600(state: &mut [u8; 200]) {
  let mut lanes = Vec::with_capacity(25);
  for x in 0..5 {
    for y in 0..5 {
      let i = 8 * (x + 5 * y);
      lanes.push(load64(&state[i..i + 8]).expect("Failure in load64 logic"))
    }
  }
  keccak_f1600_on_lanes(&mut lanes);
  // this for loop gives you a clippy warning, but it avoids a scolding by the borrow checker.
  for i in 0..state.len() {
    state[i] = 0;
  }
  for x in 0..5 {
    for y in 0..5 {
      let i = 8 * (x + 5 * y);
      for (j, k) in (i..i + 8).enumerate() {
        state[k] = store64(lanes[y + 5 * x])[j];
      }
    }
  }
}

fn keccak_hash(
  rate: u16,
  capacity: u16,
  input_bytes: &[u8],
  delimited_suffix: u8,
  output_byte_len: u16,
) -> Result<Vec<u8>, HashError> {
  if rate + capacity != 1600 {
    return Err(HashError::Capacity);
  } else if (rate % 8) != 0 {
    return Err(HashError::Rate);
  }
  let mut output_byte_len = output_byte_len;
  let mut output_bytes = Vec::with_capacity(output_byte_len as usize);
  let mut state = [0u8; 200];
  let rate_in_bytes = (rate / 8) as usize;
  let mut block_size = 0;
  let mut input_offset = 0;
  while input_offset < input_bytes.len() {
    block_size = min(input_bytes.len() - input_offset, rate_in_bytes as usize);
    for i in 0..block_size {
      state[i] ^= input_bytes[i + input_offset];
    }
    input_offset += block_size;
    if block_size == rate_in_bytes {
      keccak_f1600(&mut state);
      block_size = 0;
    }
  }
  // Do the padding & switch to the squeezing phase
  state[block_size] ^= delimited_suffix;
  if delimited_suffix & 0x80 != 0 && block_size == (rate_in_bytes - 1) {
    keccak_f1600(&mut state);
  }
  state[rate_in_bytes - 1] ^= 0x80;
  keccak_f1600(&mut state);
  // Squeeze out all the output blocks
  while output_byte_len > 0 {
    block_size = min(output_byte_len as usize, rate_in_bytes);
    for b in &state[..block_size] {
      output_bytes.push(*b);
    }
    output_byte_len -= block_size as u16;
    if output_byte_len > 0 {
      keccak_f1600(&mut state);
    }
  }

  Ok(output_bytes)
}

/// Cryptographic hash variants
/// `Shake` variants require output byte length. Note that all `Sha` variants
/// are based on the SHA3 algorithm, rather than SHA2.
pub enum Keccak {
  Shake128(u16),
  Shake256(u16),
  Sha224,
  Sha256,
  Sha384,
  Sha512,
}

impl Keccak {
  /// Hashing function for each Keccak variant.
  /// Input should be a message encoded as bytes, i.e. `"SECRET MESSAGE".as_bytes()`
  pub fn hash(&self, input_bytes: &[u8]) -> Result<Vec<u8>, HashError> {
    match self {
      Self::Shake128(output_byte_len) => {
        keccak_hash(1344, 256, input_bytes, 0x1F, *output_byte_len)
      }
      Self::Shake256(output_byte_len) => {
        keccak_hash(1088, 512, input_bytes, 0x1F, *output_byte_len)
      }
      Self::Sha224 => keccak_hash(1152, 448, input_bytes, 0x06, 224 / 8),
      Self::Sha256 => keccak_hash(1088, 512, input_bytes, 0x06, 256 / 8),
      Self::Sha384 => keccak_hash(832, 768, input_bytes, 0x06, 384 / 8),
      Self::Sha512 => keccak_hash(576, 1024, input_bytes, 0x06, 512 / 8),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rol64_works_with_max_a_and_max_n() {
    let a = u64::MAX;
    let n = u64::MAX;
    let res = rol64(a, n);
    assert_eq!(18446744073709551615, res);
  }

  #[test]
  fn rol64_works_with_max_a_and_min_n() {
    let a = u64::MAX;
    let n = 0;
    let res = rol64(a, n);
    assert_eq!(18446744073709551615, res);
  }

  #[test]
  fn rol64_works_with_min_a_and_max_n() {
    let a = 0;
    let n = u64::MAX;
    let res = rol64(a, n);
    assert_eq!(0, res);
  }

  #[test]
  fn rol64_works_with_min_a_and_min_n() {
    let a = 0;
    let n = 0;
    let res = rol64(a, n);
    assert_eq!(0, res);
  }

  #[test]
  fn store64_works_with_max_u64() {
    let x = u64::MAX;
    let res = store64(x);
    assert_eq!(res, vec![255; 8]);
  }

  #[test]
  fn store64_works_with_min_u64() {
    let x = 0;
    let res = store64(x);
    assert_eq!(res, vec![0; 8]);
  }

  #[test]
  fn load64_works_with_max_u8() {
    let v = vec![u8::MAX; 8];
    let res = load64(&v).unwrap();
    assert_eq!(res, 18446744073709551615);
  }

  #[test]
  fn load64_works_with_min_u8() {
    let v = [0u8; 8];
    let res = load64(&v).unwrap();
    assert_eq!(res, 0);
  }

  #[test]
  fn keccak_f1600_on_lanes_works() {
    let mut state = Vec::with_capacity(200);
    for i in 0..200 {
      state.push(i);
    }
    let mut lanes = Vec::with_capacity(25);
    for x in 0..5 {
      for y in 0..5 {
        let i = 8 * (x + 5 * y);
        lanes.push(load64(&state[i..i + 8]).unwrap());
      }
    }
    keccak_f1600_on_lanes(&mut lanes);
    let checked = vec![
      1308456176875568378,
      1044737440444857520,
      6134937022052046598,
      2442563609193396196,
      10577279473620415274,
    ];
    assert_eq!(checked, lanes[..5]);
  }

  #[test]
  fn keccak_f1600_works() {
    let mut state = [0u8; 200];
    for i in 0..200 {
      state[i] = i as u8;
    }
    keccak_f1600(&mut state);
    let checked = vec![
      250, 124, 213, 218, 245, 145, 40, 18, 33, 41, 118, 220, 167, 229, 248, 184, 94, 183, 117, 2,
      140, 15, 172, 143, 53, 69, 49, 116, 150, 3, 238, 71, 44, 150, 140, 203, 109, 168, 212, 23,
      176, 60, 68, 181, 42, 167, 127, 14, 62, 40, 49, 107, 209, 182, 175, 236, 9, 81, 188, 8, 52,
      146, 3, 204, 59, 2, 229, 29, 148, 218, 98, 248, 8, 156, 196, 242, 110, 157, 182, 149, 6, 23,
      206, 158, 183, 172, 35, 85, 26, 222, 120, 252, 36, 110, 0, 36, 178, 218, 25, 176, 6, 62, 11,
      41, 180, 209, 47, 235, 46, 65, 184, 227, 84, 182, 199, 44, 65, 170, 173, 49, 228, 183, 68,
      75, 169, 186, 229, 33, 157, 3, 92, 149, 142, 129, 220, 121, 67, 93, 49, 81, 189, 196, 28,
      228, 194, 64, 253, 228, 252, 160, 62, 124, 234, 97, 120, 54, 13, 53, 223, 13, 42, 243, 44,
      243, 163, 11, 202, 146, 221, 204, 119, 197, 2, 103, 137, 163, 222, 169, 188, 218, 229, 194,
      199, 111, 89, 65, 15, 246, 86, 132, 161, 15, 22, 174, 15, 227, 212, 129, 8, 7,
    ];
    assert_eq!(checked, state);
  }

  #[test]
  fn sha3_256_works() {
    let msg = "hello".as_bytes();
    let res = Keccak::Sha256.hash(msg).unwrap();
    let expected = vec![
      51, 56, 190, 105, 79, 80, 197, 243, 56, 129, 73, 134, 205, 240, 104, 100, 83, 168, 136, 184,
      79, 66, 77, 121, 42, 244, 185, 32, 35, 152, 243, 146,
    ];
    assert_eq!(expected, res);
  }
}
