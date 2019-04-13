# git2_credentials

Provide credentials function to used with [git2](https://crates.io/crates/git2)::[RemoteCallbacks.credentials](https://docs.rs/git2/0.8.0/git2/struct.RemoteCallbacks.html#method.credentials)

## Credit

Code *extracted* from:

- [cargo/utils.rs at master · rust-lang/cargo](https://github.com/rust-lang/cargo/blob/master/src/cargo/sources/git/utils.rs) (search `with_authentication`)
  > Cargo, a package manager for Rust. 
- [ffizer](https://crates.io/crates/ffizer)
  > ffizer is a files and folders initializer / generator. Create any kind (or part) of project from template.

## Links

- ["authentication required but no callback set" on clone with SSH url · Issue #41 · rust-lang/git2-rs](https://github.com/rust-lang/git2-rs/issues/41)
