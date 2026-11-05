# Repository Guidelines

## Project Structure & Module Organization

Workspace crates under `crates/` (macOS only):

- `tunlatch-core`: validated configuration and protection states; no system dependencies.
- `tunlatch-platform`: native discovery, configuration reads, and PF boundary.
- `tunlatch-ipc`: versioned messages, private Unix sockets, and peer checks.
- `tunlatchd`: service orchestration, client limits, and shutdown.
- `tunlatch`: CLI and Ratatui dashboard.

Unit tests sit beside implementations; socket integration tests occupy `crates/tunlatchd/tests/`. Sample configuration: `examples/config.toml`. `docs/` is ignored local planning material; shared guidance belongs in tracked Markdown. Build output: ignored `target/`.

## Build, Test, and Development Commands

Use macOS, Rustup, and Xcode Command Line Tools. `rust-toolchain.toml` pins Rust 1.99.1; run commands from the repository root:

```sh
cargo build --workspace --locked                         # Build all crates
cargo fmt --all -- --check                              # Check formatting
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked            # Unit/integration tests
cargo test --workspace --doc --locked                    # Documentation tests
cargo run -p tunlatch -- config check examples/config.toml
```

Clippy rejects warnings. Create a private directory using `mktemp -d /tmp/tunlatch.XXXXXX`; pass its path as `--runtime-dir` to `cargo run -p tunlatchd --` and `cargo run -p tunlatch -- tui`. Follow `.github/workflows/ci.yml` for the complete check sequence, including release builds, rustdoc, and pinned cargo-deny checks.

## Coding Style & Naming Conventions

Rust 2024: four-space indentation, 100-column rustfmt width; YAML: two spaces. Use `snake_case` for modules/functions and `UpperCamelCase` for types. New crates inherit workspace metadata, dependencies, and lints. Use typed errors; avoid `unwrap`, `expect`, and explicit panics. Workspace code denies `unsafe`. Document public contracts; isolate native network/PF integration in `tunlatch-platform`.

## Testing Guidelines

Use `#[test]`, `#[tokio::test]`, and Ratatui's `TestBackend`. Name tests after behavior, such as `rejects_mutations_and_extra_fields`. No numeric coverage threshold is configured; exercise success and failure paths for permissions, framing, configuration, state, and recovery. Routine tests must run without root or PF writes. Model/socket tests do not establish real leak protection.

## Commit & Pull Request Guidelines

Use `feat(<scope>): <summary>` for commit subjects, e.g. `feat(scaffold): establish Rust workspace and engineering checks`. Choose concrete scopes and imperative summaries. Keep commits focused. PRs describe behavior, issues, validation, and limitations; include captures for TUI changes. Update `Cargo.lock` with dependencies.

Once code changes or additions form a coherent, independently reviewable commit and their relevant checks pass, commit them promptly without waiting for another request. Before staging new files, decide whether they belong in version control or `.gitignore`; keep generated output, local evidence, sensitive data, and unrelated work out of the commit.

## Security & Configuration Boundaries

The service is a read-only observer; PF enforcement is unimplemented. Separate desired, committed, and observed states; never present unknown protection as active. Interface names/indices never establish trust. Keep IPC bounded and same-user. Resource cleanup must not disable protection. Read `SAFETY.md` before changing privileges, PF, or recovery.
