# `@upstash/box` examples for boxd

These examples use the published `@upstash/box@0.6.3` package and exercise a
running boxd instance through its public `/v2/box` compatibility API. They do
not import boxd internals.

## Prerequisites

- Node.js 22 or newer;
- a running boxd whose `/health/ready` endpoint returns HTTP 200;
- an installed runtime bundle matching each example (`node`, plus Browser
  support for `02-browser.mjs`);
- a compatibility API key created by `boxd init` or the admin API.

Install the exact SDK version:

```sh
cd examples
npm ci
npm run check
```

Set the endpoint and key explicitly. Requiring the base URL prevents an example
from accidentally using a different service when the local variable is absent.

```sh
export UPSTASH_BOX_BASE_URL=http://127.0.0.1:7331
export UPSTASH_BOX_API_KEY='<the one-time compatibility API key>'
```

Never commit the API key or put it in `boxd.toml`.

## Run the examples

```sh
npm run lifecycle
npm run browser
npm run schedule
npm run snapshot
npm run ephemeral
npm run network-policy
```

| Script | Demonstrates | Notes |
| --- | --- | --- |
| `01-lifecycle.mjs` | create, env, command/code, files, labels, pause/resume, delete | Uses `deny-all`; always deletes the box. |
| `02-browser.mjs` | Browser tab, content, PNG screenshot, CDP ticket | Uses restricted-default egress when policy is omitted. Set `BOXD_EXAMPLE_URL` to override the URL. The screenshot is created with exclusive-write semantics. |
| `03-schedule.mjs` | create/pause/resume/get/delete an exec schedule | Waits up to 90 seconds for the next UTC cron minute. |
| `04-snapshot.mjs` | snapshot, restore, verify persisted file, cleanup | Requires enough disk space for the restored box. |
| `05-ephemeral.mjs` | TTL box, exec and file roundtrip | Uses a 300-second TTL and also deletes explicitly. |
| `06-network-policy.mjs` | custom domain/CIDR policy | Requires `features.custom_network_policy=true`; verifies one allowed public domain and one disallowed public domain. |

To choose a different browser target or output file:

```sh
BOXD_EXAMPLE_URL=https://example.org \
BOXD_EXAMPLE_SCREENSHOT=/tmp/boxd-example.png \
  npm run browser
```

The examples deliberately avoid managed-agent credentials and `attach_headers` secrets.
`attach_headers` is available only when `features.attach_headers=true`, and should be
verified against an operator-controlled endpoint without printing the injected value.
Nested tree download is also not used: the
pinned SDK cannot preserve nested local directories, so boxd returns a truthful
HTTP 501 for that case. See `docs/manual/boxd-local-sandbox-testing.md` for the
full build, runtime import, doctor, and manual validation procedure.
