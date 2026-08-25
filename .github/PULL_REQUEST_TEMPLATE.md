## Outcome

Describe the user-visible result and why it belongs in boxd.

## Compatibility and security

- Affected pinned SDK routes/types/streams:
- Unsupported behavior remains explicit 501: yes / not applicable
- Secret and tenant/account boundary tests:

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Relevant Node contract, Console, or docs checks
- [ ] Native HVF/KVM evidence stated separately when required

## Remaining external gates

List credentials, signing, runtime assets, hosted services, or native runners
that were not available. Do not present source tests as those external results.
