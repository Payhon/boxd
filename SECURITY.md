# Security policy

## Supported versions

boxd is under active pre-1.0 development. Security fixes are applied to the
current `main` branch. No released version should be assumed production-ready
until the Phase 4 gates documented in the development blueprint pass.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting for `Payhon/boxd` when available. If that
channel is unavailable, contact the repository owner privately through the
contact method on the maintainer's GitHub profile and ask for a secure reporting
channel before sharing sensitive details.

Include, when safe:

- affected commit and platform;
- preconditions and impact;
- minimal reproduction steps;
- whether secrets, tenant boundaries, guest isolation, filesystem paths,
  Preview, networking, or VMM behavior are involved;
- suggested remediation, if known.

Do not include live API keys, user data, signing keys, or harmful payloads in
the first contact. Maintainers will acknowledge receipt and coordinate a
disclosure timeline based on severity and reproducibility.

## Scope reminders

The primary security boundaries include the guest microVM, libkrun worker
process, account/tenant authorization, secret redaction, runtime supply chain,
egress/SSRF policy, filesystem path handling, Preview, and one-time Terminal
capabilities.
