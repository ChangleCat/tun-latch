# Contributing to TunLatch

Thanks for taking a look. TunLatch is a macOS-only Rust project. The current `main` branch is a
read-only observer and offline toolset; PF enforcement and real leak protection are not implemented.
Chinese and English discussion are both welcome. Please read [README.md](README.md) and
[SAFETY.md](SAFETY.md) before changing behavior.

## Platform support

- **macOS**: the full workspace, service, CLI, and TUI.
- **Linux**: documentation, most Python helper checks, and `tunlatch-core` only.

`tunlatch-platform` contains an explicit `compile_error!` on non-macOS targets, so
`tunlatch-ipc`, `tunlatchd`, and `tunlatch` cannot be built or tested on Linux. On Linux, use
`cargo test -p tunlatch-core --locked`; do not run `cargo test --workspace` or workspace-wide
Clippy. A few script tests invoke macOS tools such as `/usr/bin/script`; those are verified on
macOS CI. CI currently runs on `macos-15` only.

## Before you start

- Use macOS with Rustup and the Xcode Command Line Tools.
- `rust-toolchain.toml` pins Rust 1.99.1. Do not use a nightly toolchain.
- Pick an issue tagged `good first issue` or `help wanted`, and comment to claim it.
- Small documentation fixes can be sent directly. Behavior changes should start with an issue;
  design changes should use the `needs-design` form.
- One issue per pull request. Keep the diff focused and avoid unrelated refactors.

## Set up

```sh
git clone https://github.com/ChangleCat/tun-latch.git
cd tun-latch
cargo build --workspace --locked
cargo run -p tunlatch -- config check examples/config.toml
```

The service and TUI are optional for most contributions. If you need them, use a private temporary
runtime directory:

```sh
TUNLATCH_RUNTIME_DIR=$(mktemp -d /tmp/tunlatch.XXXXXX)
cargo run -p tunlatchd -- --runtime-dir "$TUNLATCH_RUNTIME_DIR"
cargo run -p tunlatch -- status --runtime-dir "$TUNLATCH_RUNTIME_DIR" --json
```

Do not install a service, run as root, or point the tools at a production configuration.

## Checks

Run the checks that cover your change. Before requesting review, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
```

For a targeted change, `cargo test -p <crate> --test <name> --locked` is fine during development,
but the PR should be based on the full workspace result. The complete sequence, including the
release build and pinned `cargo-deny` check, is in
[.github/workflows/ci.yml](.github/workflows/ci.yml). CI runs on `macos-15`.

Python helper tests are not yet part of CI. If you change `scripts/`, run:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
```

## Pull requests

- Describe the behavior change, the linked issue, the commands you ran, and any limitation.
- Add a success test and a failure test for new behavior. A model or mock test does not prove real
  PF or leak protection.
- Use `type(scope): summary` for commit subjects, for example `feat(scaffold): establish workspace`.
- Update documentation and `Cargo.lock` when the change requires it.
- Reference the issue with `Closes #<number>` in the PR description.

## What not to do

- Do not run or script real PF writes, root operations, service installation, reboot/sleep tests, or
  network-changing experiments for a PR. Use unit tests, mocks, and `TestBackend`.
- Do not add `unsafe` code. The workspace denies it; the one reviewed read-only adapter exception is
  documented in [AGENTS.md](AGENTS.md). A new `unsafe` use needs a design issue and maintainer
  review before implementation.
- Do not change privilege, authorization, IPC trust, or recovery boundaries without a design issue.
- Do not commit local paths, PIDs, session names, credentials, packet captures, proxy subscriptions,
  node addresses, or local planning evidence.
- Do not weaken or delete tests to make a change pass.

## Security reports

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## License

TunLatch is licensed under GPL-3.0-only. By submitting a pull request, you agree that your
contribution is distributed under the same license.
