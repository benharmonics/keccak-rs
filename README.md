# keccak-rs
Implementing Keccak hashing functions (SHA3 and SHAKE) in Rust

As a library, the primary object is an enum with several variants:

```rust
pub enum Keccak {
    Shake128(u16),
    Shake256(u16),
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}
```

Which you can then call to hash a message as follows:

```rust
// use keccak_rs::Keccak;
let msg = "hello".as_bytes();
let hash = Keccak::Sha256.hash(msg).unwrap();
```

The two SHAKE variants require you to supply an output byte length; e.g. to get an output of 45 bytes:

```rust
let msg = "hello".as_bytes();
let hash = Keccak::Shake256(45).hash(msg).unwrap();
```
