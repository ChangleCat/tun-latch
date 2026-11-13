## What changed

## Linked issue

Closes #

## Behavior

What is different after this change? What is intentionally unchanged?

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --all-targets --locked`
- [ ] `cargo test --workspace --doc --locked`
- [ ] New behavior has a success test and a failure test

## Safety

- [ ] No root, PF writes, routing, install, reboot, or network changes
- [ ] No new unsafe code, or a linked design issue
- [ ] No local paths, PIDs, secrets, packet captures, or operator evidence
- [ ] No unrelated refactor
- [ ] Tests do not weaken or skip existing assertions

## Limitations

What is still unverified or intentionally out of scope?
