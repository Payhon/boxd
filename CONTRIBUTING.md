# Contributing to boxd

Thank you for helping improve boxd. Contributions are welcome as issues,
documentation, tests, platform evidence, compatibility fixtures, and code.

## Before you start

1. Read `blueprint/boxd-development-blueprint.md` as the product, architecture,
   and acceptance baseline.
2. Search existing issues before opening a new one.
3. For security vulnerabilities, follow `SECURITY.md` instead of filing a
   public issue.
4. Keep a change focused on one reviewable vertical slice.

## Compatibility rules

- `/v2/box` follows the executable contract of `@upstash/box@0.6.3` at commit
  `677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`.
- Do not infer DTOs or routes. Update the pinned fixture/manifest first.
- Unsupported semantics must return HTTP 501 `feature_not_supported`.
- Salvo handlers must not access SeaORM, disk, or libkrun directly.
- Add tests for secret redaction and account/tenant boundaries.

## Local checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace

npm ci --prefix compat/upstash-box-0.6.3
npm test --prefix compat/upstash-box-0.6.3
```

For documentation changes:

```sh
npm ci --prefix docs
npm run check --prefix docs
```

Run the Console checks when changing `web/console`. Native HVF/KVM evidence
must be reported separately from source tests or hosted CI.

## Pull requests

- Explain the user-visible result and compatibility impact.
- List exact checks that completed and any external gate that remains pending.
- Include screenshots for documentation or Console UI changes.
- Do not commit API keys, signing material, runtime disks, databases, or logs
  containing secrets.

By contributing, you agree that your contribution is licensed under the
project's MIT License.
