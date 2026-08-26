# boxd documentation

This directory contains both the Rspress website project and engineering
evidence used by the repository.

## Website project

- Rspress config: `rspress.config.ts`
- Website source: `site/`
- Custom theme: `theme/`
- Integrity check: `scripts/check-docs.mjs`
- Generated output: `doc_build/` (ignored by Git)

Use Node 22.x:

```sh
npm ci --prefix docs
npm run dev --prefix docs
npm run check --prefix docs
```

Local development uses `/`; the production build uses the GitHub Pages base
path `/boxd/` and is published at <https://payhon.github.io/boxd/>.

The primary installation path is the public binary download page at
`site/guide/download.md`. It links to target-specific GitHub prerelease assets;
source compilation remains a contributor/auditor path rather than the default
user onboarding flow.

## Engineering documents

Existing architecture decisions, implementation status, phase evidence, and
manuals remain in this directory outside `site/`. The public website summarizes
them for users, while the repository documents retain the complete executable
evidence and acceptance boundary.

GitHub Pages must use **GitHub Actions** as its source in repository Settings.
The workflow at `.github/workflows/docs-pages.yml` validates pull requests and
deploys pushes to `main`.
