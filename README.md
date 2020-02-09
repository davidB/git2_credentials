# git2_credentials

[![crate license](https://img.shields.io/crates/l/git2_credentials.svg)](https://spdx.org/licenses/Apache-2.0.html)
[![crate version](https://img.shields.io/crates/v/git2_credentials.svg)](https://crates.io/crates/git2_credentials)

[![Actions Status](https://github.com/davidB/git2_credentials/workflows/ci-flow/badge.svg)](https://github.com/davidB/git2_credentials/actions)

Provide credentials function to used with [git2](https://crates.io/crates/git2)::[RemoteCallbacks.credentials](https://docs.rs/git2/0.8.0/git2/struct.RemoteCallbacks.html#method.credentials)

## Usage

```rust
use git2;
use git2_credentials::CredentialHandler;
use tempfile;

let mut cb = git2::RemoteCallbacks::new();
let git_config = git2::Config::open_default().unwrap();
let mut ch = CredentialHandler::new(git_config);
cb.credentials(move |url, username, allowed| ch.try_next_credential(url, username, allowed));

// clone a repository
let mut fo = git2::FetchOptions::new();
fo.remote_callbacks(cb)
    .download_tags(git2::AutotagOption::All)
    .update_fetchhead(true);
let dst = tempfile::tempdir().unwrap();
std::fs::create_dir_all(&dst.as_ref()).unwrap();
git2::build::RepoBuilder::new()
    .branch("master")
    .fetch_options(fo)
    .clone("git@github.com:davidB/git2_credentials.git", dst.as_ref()).unwrap();
```

You can run the example via

```sh
cargo run --example clone -- --nocapture
```

You can provide custom UI (to ask password, passphrase) by providing a `CredentialUI`. A default implementation (with [dialoguer](https://crates.io/crates/dialoguer) is provided.

### Build

```sh
cargo make ci-flow
```

## Credit

Code *extracted* from:

- [cargo/utils.rs at master · rust-lang/cargo](https://github.com/rust-lang/cargo/blob/master/src/cargo/sources/git/utils.rs) (search `with_authentication`)
  > Cargo, a package manager for Rust.
- [ffizer](https://crates.io/crates/ffizer)
  > ffizer is a files and folders initializer / generator. Create any kind (or part) of project from template.
- [gpm/ssh.rs at master · aerys/gpm](https://github.com/aerys/gpm/blob/master/src/gpm/ssh.rs)
  > Git-based package manager.

## Links

- ["authentication required but no callback set" on clone with SSH url · Issue #41 · rust-lang/git2-rs](https://github.com/rust-lang/git2-rs/issues/41)
