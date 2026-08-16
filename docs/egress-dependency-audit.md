# Restricted-default egress dependency audit

## Scope

This audit covers the packet-stack candidates named by
[ADR-0006](adr/0006-restricted-default-egress.md). Production acceptance is
recorded separately in that ADR and the Phase 1 acceptance record.

## Rejected adapter: `netstack-smoltcp 0.2.4`

- crate archive SHA-256: `4c38f66cdd673ff0e760752f27c6d34a7e3a140f0b1eea9efae3c46d8867c83d`;
- declared license: `MIT OR Apache-2.0`;
- MSRV: Rust 1.75;
- source contains an `unsafe impl Send` for a boxed future whose erased future is not required to
  be `Send`;
- TCP stream creation and virtual-device ingress use unbounded Tokio channels;
- the adapter defaults to roughly 320 KiB send and receive buffers per accepted TCP flow and does
  not expose a hard connection-count admission boundary.

Those properties conflict with the required per-Box memory/connection caps and the repository's
unsafe boundary. This version is rejected and is not present in workspace manifests or the lockfile.

## Conditional primitive: `smoltcp 0.12.0`

- crate archive SHA-256: `dad095989c1533c1c266d9b1e8d70a1329dd3723c3edac6d03bbd67e7bf6f4bb`;
- `LICENSE-0BSD.txt` SHA-256:
  `beb2cad88fab8447f7975564e21f9506e733e14c344836f146fa02e811216694`;
- declared license: `0BSD`;
- MSRV: Rust 1.80;
- crate root denies unsafe code. Unsafe platform PHY modules are feature-gated and must not be
  enabled; the egress adapter may only use caller-owned in-memory Ethernet devices;
- socket buffers and socket-set storage are caller-owned, so a boxd adapter can allocate fixed
  capacity and refuse new flows;
- constructors contain documented panics for invalid caller configuration. All sizes, TTLs,
  hardware medium and handles therefore require wrapper validation and panic-boundary tests.

Acceptance requires `default-features = false` with only the exact Ethernet,
IPv4, DHCP, DNS, TCP and fixed-capacity features needed by the adapter. Raw socket, TUN/TAP, BPF,
IPv6, fragmentation, ICMP and multicast features are prohibited for Phase 1.

`smoltcp` is pinned exactly at `0.12.0`; its license and provenance are archived under
`crates/box-egress/third-party`. The manifest disables defaults and records the exact allowlist.
The DHCP/DNS/TCP proxy and macOS L2/HVF gates in ADR-0006 are complete; Linux
KVM remains a separate platform gate.

## Already implemented without third-party dependencies

`box-egress` provides the shared IP classifier, DNS/TCP decision functions, payload-free audit event,
bounded libkrun unix-stream frame decoder, fail-closed guest L2 admission, and a caller-driven
smoltcp device with fixed frame/byte capacities. The device creates no channels or background tasks.
These pieces are wired to the production DHCP/DNS/TCP proxy with bounded
channels, connection admission and fail-closed Unix-stream ownership.
