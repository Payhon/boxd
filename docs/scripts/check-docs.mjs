import { access, readFile, readdir, stat } from 'node:fs/promises';
import { resolve } from 'node:path';

const docsRoot = resolve(import.meta.dirname, '..');
const repoRoot = resolve(docsRoot, '..');
const required = [
  'site/index.mdx',
  'site/guide/download.md',
  'site/guide/source-build.md',
  'site/api/overview.md',
  'site/api/errors.md',
  'site/mobile/components.md',
  'site/community/license.md',
  'site/public/logo.svg',
  'site/public/favicon.svg',
  'site/public/boxd-hero.png',
  'theme/Flowchart.tsx',
  'rspress.config.ts',
  '../.github/workflows/docs-pages.yml',
  '../.github/workflows/release-binaries.yml',
];

for (const file of required) await access(resolve(docsRoot, file));

const [
  readme,
  license,
  cargo,
  packageJson,
  packageLock,
  rspressConfig,
  workflow,
  releaseWorkflow,
  home,
  download,
  sourceBuild,
  apiOverview,
  apiErrors,
  compatibility,
  introduction,
  architecture,
  mobileOverview,
  flowchartComponent,
  mobileComponents,
  routeManifest,
  coverageTable,
  hero,
] = await Promise.all([
  readFile(resolve(repoRoot, 'README.md'), 'utf8'),
  readFile(resolve(repoRoot, 'LICENSE'), 'utf8'),
  readFile(resolve(repoRoot, 'Cargo.toml'), 'utf8'),
  readFile(resolve(docsRoot, 'package.json'), 'utf8').then(JSON.parse),
  readFile(resolve(docsRoot, 'package-lock.json'), 'utf8').then(JSON.parse),
  readFile(resolve(docsRoot, 'rspress.config.ts'), 'utf8'),
  readFile(resolve(repoRoot, '.github/workflows/docs-pages.yml'), 'utf8'),
  readFile(resolve(repoRoot, '.github/workflows/release-binaries.yml'), 'utf8'),
  readFile(resolve(docsRoot, 'site/index.mdx'), 'utf8'),
  readFile(resolve(docsRoot, 'site/guide/download.md'), 'utf8'),
  readFile(resolve(docsRoot, 'site/guide/source-build.md'), 'utf8'),
  readFile(resolve(docsRoot, 'site/api/overview.md'), 'utf8'),
  readFile(resolve(docsRoot, 'site/api/errors.md'), 'utf8'),
  readFile(resolve(docsRoot, 'site/concepts/compatibility.md'), 'utf8'),
  readFile(resolve(docsRoot, 'site/guide/introduction.mdx'), 'utf8'),
  readFile(resolve(docsRoot, 'site/concepts/architecture.mdx'), 'utf8'),
  readFile(resolve(docsRoot, 'site/mobile/overview.mdx'), 'utf8'),
  readFile(resolve(docsRoot, 'theme/Flowchart.tsx'), 'utf8'),
  readFile(resolve(docsRoot, 'site/mobile/components.md'), 'utf8'),
  readFile(resolve(repoRoot, 'compat/upstash-box-0.6.3/route-manifest.json'), 'utf8').then(JSON.parse),
  readFile(resolve(repoRoot, 'compat/upstash-box-0.6.3/coverage-table.json'), 'utf8').then(JSON.parse),
  stat(resolve(docsRoot, 'site/public/boxd-hero.png')),
]);

const extraction = routeManifest.extraction;
const expectedContractSummary =
  `${extraction.raw_call_sites} callsites / ` +
  `${extraction.normalized_operation_dispatches} operations / ` +
  `${extraction.direct_method_path_contracts} direct + ` +
  `${extraction.response_linked_contracts} response-linked contracts`;

const assertions = [
  [readme.includes('https://payhon.github.io/boxd/'), 'README must link to GitHub Pages'],
  [license.startsWith('MIT License\n'), 'root LICENSE must contain the MIT License'],
  [/license = "MIT"/.test(cargo), 'Cargo workspace license must be MIT'],
  [packageJson.engines.node === '>=22 <23', 'documentation must retain the verified Node 22 engine'],
  [packageJson.devDependencies['@rspress/core'] === '2.0.20', 'Rspress version must stay explicitly pinned'],
  [packageJson.devDependencies.mermaid === '11.17.2', 'Mermaid version must stay explicitly pinned'],
  [packageLock.packages[''].devDependencies['@rspress/core'] === '2.0.20', 'package lock must pin Rspress 2.0.20'],
  [packageLock.packages[''].devDependencies.mermaid === '11.17.2', 'package lock must pin Mermaid 11.17.2'],
  [rspressConfig.includes("root: 'site'"), 'Rspress root must remain docs/site'],
  [rspressConfig.includes("'/boxd/'"), 'Rspress production base must remain /boxd/'],
  [rspressConfig.includes('checkDeadLinks: true'), 'Rspress dead-link checking must remain enabled'],
  [home.includes('src: ./boxd-hero.png'), 'homepage hero must use a base-safe relative URL'],
  [home.includes('@upstash/box@0.6.3'), 'homepage must name the pinned SDK baseline'],
  [home.includes('/guide/download'), 'homepage must lead users to binary downloads'],
  [download.includes('https://github.com/Payhon/boxd/releases'), 'download guide must link to GitHub Releases'],
  [download.includes('runtime bundle'), 'download guide must retain the separate runtime boundary'],
  [download.includes('prerelease'), 'download guide must retain the pre-1.0 release boundary'],
  [workflow.includes('branches: [main]'), 'Pages workflow must deploy the default main branch'],
  [workflow.includes('npm ci --prefix docs'), 'Pages workflow must use the documentation lockfile'],
  [workflow.includes('npm run check --prefix docs'), 'Pages workflow must run the full documentation gate'],
  [workflow.includes('path: docs/doc_build'), 'Pages artifact must upload the Rspress output directory'],
  [workflow.includes('actions/checkout@v7'), 'Pages workflow must use the current Node 24 checkout action'],
  [workflow.includes('actions/setup-node@v7'), 'Pages workflow must use the current Node 24 setup-node action'],
  [workflow.includes('actions/configure-pages@v6'), 'Pages workflow must use the current Node 24 configure-pages action'],
  [workflow.includes('actions/deploy-pages@v5'), 'Pages workflow must use the reviewed deploy action major'],
  [releaseWorkflow.includes('linux-x86_64'), 'release workflow must build Linux x86_64'],
  [releaseWorkflow.includes('linux-aarch64'), 'release workflow must build Linux aarch64'],
  [releaseWorkflow.includes('darwin-arm64'), 'release workflow must build macOS ARM64'],
  [releaseWorkflow.includes('scripts/phase1-linux-kvm-smoke.sh'), 'release workflow must retain the real Linux KVM gate'],
  [releaseWorkflow.includes('--prerelease'), 'release workflow must retain the pre-1.0 publication boundary'],
  [sourceBuild.includes('git clone https://github.com/Payhon/boxd.git'), 'source guide must start from repository clone'],
  [sourceBuild.includes('BOXD_EMBEDDED_LIBKRUN_PATH'), 'source guide must include release asset build'],
  [sourceBuild.includes('doctor --json'), 'source guide must include doctor gate'],
  [sourceBuild.includes('/health/ready'), 'source guide must verify service readiness'],
  [sourceBuild.includes('npm run lifecycle'), 'source guide must finish with a real public-SDK lifecycle'],
  [apiOverview.includes('/openapi.json'), 'API overview must document generated OpenAPI'],
  [apiOverview.includes('X-Box-Api-Key'), 'API overview must document compatibility authentication'],
  [apiErrors.includes(expectedContractSummary), 'API compatibility counts must match the pinned manifest'],
  [compatibility.includes(`${coverageTable.public_cases} cases / ${coverageTable.captured_dispatches} captures`), 'compatibility page counts must match coverage evidence'],
  [introduction.includes('<Flowchart'), 'introduction must render its request flow as a diagram'],
  [architecture.includes('<Flowchart'), 'architecture must render process boundaries as a diagram'],
  [mobileOverview.includes('<Flowchart'), 'mobile overview must render its access flow as a diagram'],
  [flowchartComponent.includes("securityLevel: 'strict'"), 'flowcharts must retain strict Mermaid rendering'],
  [flowchartComponent.includes("classList.contains('dark')"), 'flowcharts must follow the documentation color theme'],
  [mobileComponents.includes('文档级 React Native 参考实现'), 'mobile components must retain reference-only boundary'],
  [mobileComponents.includes('BoxStatusCardProps'), 'mobile docs must include BoxStatusCard API'],
  [mobileComponents.includes('RunEventListProps'), 'mobile docs must include RunEventList API'],
  [mobileComponents.includes('SandboxActionsProps'), 'mobile docs must include SandboxActions API'],
  [hero.size > 100_000, 'hero artwork is unexpectedly small'],
];

for (const [condition, message] of assertions) {
  if (!condition) throw new Error(message);
}

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(
    entries.map((entry) => {
      const path = resolve(directory, entry.name);
      return entry.isDirectory() ? sourceFiles(path) : [path];
    }),
  );
  return files.flat();
}

const textualSources = (await sourceFiles(resolve(docsRoot, 'site'))).filter((file) =>
  /\.(?:md|mdx|json|ts|tsx|svg)$/.test(file),
);

for (const file of textualSources) {
  const content = await readFile(file, 'utf8');
  if (content.includes('@upslash/box')) {
    throw new Error(`${file.slice(docsRoot.length + 1)} contains the misspelled package name @upslash/box`);
  }
}

console.log(
  `docs integrity OK: ${required.length} required files, ` +
    `${routeManifest.routes.length} pinned contracts, ` +
    `${coverageTable.public_cases} SDK cases, hero ${hero.size} bytes`,
);
