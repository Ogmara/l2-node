//! Ogmara L2 node — library surface for integration tests.
//!
//! `main.rs` carries the full module tree as `mod foo;` declarations
//! (binary-internal). This `lib.rs` re-declares the subset that
//! integration tests in `tests/` need to construct types — chiefly
//! `IpfsClient` against a fake-Kubo server. The bin and lib compile
//! the same source files independently, so behavior is identical;
//! they're separate type-system entities only at the test boundary.
//!
//! Add a module here only when a test in `tests/` needs it. The
//! binary keeps its module tree opaque otherwise.

pub mod config;
pub mod ipfs;
pub mod trusted_proxies;
