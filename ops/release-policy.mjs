export const PACKAGE_NAME = "raven-receipt-verifier";
export const PACKAGE_VERSION = "0.1.0";
export const CANONICAL_TARBALL = `${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz`;
export const PINNED_NPM_VERSION = "11.18.0";
export const NODE_FLOOR = ">=22.18";

export const PUBLIC_REPOSITORY =
  "git+https://github.com/billybotticelli4u-collab/raven-receipt-verifier.git";
export const PUBLIC_HOMEPAGE = "https://ravenattest.com";
export const PUBLIC_BUGS = "https://ravenattest.com/security.html";

// Publication is deliberately restricted to protected main. A workflow input
// may name this ref, but it cannot broaden the allowlist.
export const PUBLICATION_REF = "refs/heads/main";

export const UPSTREAM_ACCEPTED_COMMIT =
  "610b10ca67b2f7ddf4a131de4cf8c1da71468eb1";
export const UPSTREAM_ACCEPTED_TREE =
  "b9c8984430168f2ad0169a1466c5c1605a4de932";
export const UPSTREAM_ACCEPTED_PACKAGE_TREE =
  "b268024119ddfa18344397072200896828804190";
export const PUBLIC_MIRROR_PACKAGE_TREE =
  "da56440a505f0730203e2a0b254112fe8d19c76a";

export const CUSTOMER_MODULES = [
  "canonicalDataSnapshot",
  "canonicalJson",
  "detect",
  "index",
  "outcomeProjection",
  "receiptRules",
  "receiptV1",
  "solanaAddress",
  "trustAnchor",
  "verifyReceiptV1",
  "verifyReceiptV1ForSubject",
];

export const COMPILED_EXTENSIONS = [".d.ts", ".d.ts.map", ".js", ".js.map"];

export const EXPECTED_PACKAGE_FILES = [
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "package.json",
  ...CUSTOMER_MODULES.flatMap((moduleName) =>
    COMPILED_EXTENSIONS.map((extension) => `dist/${moduleName}${extension}`),
  ),
].sort();

export const EXPECTED_FILES_ALLOWLIST = [
  ...CUSTOMER_MODULES.map((moduleName) => `dist/${moduleName}.*`),
  "README.md",
  "LICENSE",
  "SECURITY.md",
];

export const EXPECTED_EXPORT_MAP = {
  ".": {
    types: "./dist/index.d.ts",
    import: "./dist/index.js",
    default: "./dist/index.js",
  },
};

// The only registry this ceremony may talk to. setup-node must name it, npm
// must resolve it at the publication boundary, and nothing may override it.
export const PUBLICATION_REGISTRY = "https://registry.npmjs.org";

// Every external GitHub Action in the release workflow, pinned to the exact
// reviewed commit. Changing a SHA or adding an action is a reviewed policy
// change here, never a silent workflow edit.
export const APPROVED_ACTIONS = {
  "actions/checkout": "11bd71901bbe5b1630ceea73d27597364c9af683",
  "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
  "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
  "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
};

// Exact step allowlist for every job in the release workflow. A step is
// identified by its ENTIRE normalised YAML block minus its name: (uses/run
// text, with:, env:, if:, every key). Derived from the reviewed workflow with
// ops/publication-policy.mjs#parseJobSteps. Any inserted, removed, reordered
// or edited step — run: or uses: — is a reviewed policy change here, never a
// silent workflow edit.
export const EXPECTED_JOB_STEPS = {
  "source-gate": [
    "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 with: ref: ${{ inputs.release_sha }} fetch-depth: 0 persist-credentials: false",
    "env: RAVEN_RELEASE_REF: ${{ inputs.release_ref }} RAVEN_RELEASE_SHA: ${{ inputs.release_sha }} RAVEN_RELEASE_TREE: ${{ inputs.release_tree }} run: node ops/verify-release-ref.mjs",
    "uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0 with: node-version: ${{ matrix.node-version }}",
    "run: curl -fsSL --proto '=https' --tlsv1.2 -o \"$RUNNER_TEMP/governed-npm.tgz\" \"https://registry.npmjs.org/npm/-/npm-${RAVEN_PINNED_NPM_VERSION}.tgz\"",
    "run: node ops/install-governed-npm.mjs --tarball \"$RUNNER_TEMP/governed-npm.tgz\" --dest \"$RUNNER_TEMP/governed-npm\"",
    "run: node ops/npm-version-gate.mjs --governed-npm \"$RUNNER_TEMP/governed-npm/package\"",
    "run: npm --prefix packages/verify-js ci",
    "run: npm --prefix packages/verify-js run build",
    "run: node ops/verify-byte-correspondence.mjs",
    "run: npm --prefix packages/verify-js test",
    "env: RAVEN_GOVERNED_NPM_DIR: ${{ runner.temp }}/governed-npm/package run: node --test ops/*.test.mjs"
  ],
  "package-artifact": [
    "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 with: ref: ${{ inputs.release_sha }} fetch-depth: 0 persist-credentials: false",
    "env: RAVEN_RELEASE_REF: ${{ inputs.release_ref }} RAVEN_RELEASE_SHA: ${{ inputs.release_sha }} RAVEN_RELEASE_TREE: ${{ inputs.release_tree }} run: node ops/verify-release-ref.mjs",
    "uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0 with: node-version: \"22.18.0\"",
    "run: curl -fsSL --proto '=https' --tlsv1.2 -o \"$RUNNER_TEMP/governed-npm.tgz\" \"https://registry.npmjs.org/npm/-/npm-${RAVEN_PINNED_NPM_VERSION}.tgz\"",
    "run: node ops/install-governed-npm.mjs --tarball \"$RUNNER_TEMP/governed-npm.tgz\" --dest \"$RUNNER_TEMP/governed-npm\"",
    "run: node ops/npm-version-gate.mjs --governed-npm \"$RUNNER_TEMP/governed-npm/package\"",
    "run: npm --prefix packages/verify-js ci",
    "run: set -euo pipefail mkdir -p \"$RUNNER_TEMP/release-package\" cd packages/verify-js npm pack --json --pack-destination \"$RUNNER_TEMP/release-package\" > \"$RUNNER_TEMP/release-package/pack.json\"",
    "env: GITHUB_REF: ${{ inputs.release_ref }} run: node ops/create-release-artifact-identity.mjs \\ --pack-json \"$RUNNER_TEMP/release-package/pack.json\" \\ --tarball-dir \"$RUNNER_TEMP/release-package\" \\ --out \"$RUNNER_TEMP/release-package/release-artifact-identity.json\" \\ --release-ref \"${{ inputs.release_ref }}\" \\ --governed-npm \"$RUNNER_TEMP/governed-npm/package\"",
    "run: node ops/verify-release-artifact.mjs \\ --pack-json \"$RUNNER_TEMP/release-package/pack.json\" \\ --tarball-dir \"$RUNNER_TEMP/release-package\" \\ --artifact-identity \"$RUNNER_TEMP/release-package/release-artifact-identity.json\" \\ --frozen-identity release/release-identity.json \\ --confirm-version \"${{ inputs.confirm_version }}\" \\ --release-ref \"${{ inputs.release_ref }}\" \\ --release-sha \"${{ inputs.release_sha }}\" \\ --release-tree \"${{ inputs.release_tree }}\"",
    "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2 with: path: | ${{ runner.temp }}/release-package/raven-receipt-verifier-0.1.0.tgz ${{ runner.temp }}/release-package/pack.json ${{ runner.temp }}/release-package/release-artifact-identity.json if-no-files-found: error"
  ],
  "tarball-gate": [
    "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 with: ref: ${{ inputs.release_sha }} fetch-depth: 0 persist-credentials: false",
    "env: RAVEN_RELEASE_REF: ${{ inputs.release_ref }} RAVEN_RELEASE_SHA: ${{ inputs.release_sha }} RAVEN_RELEASE_TREE: ${{ inputs.release_tree }} run: node ops/verify-release-ref.mjs",
    "uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0 with: path: ${{ runner.temp }}/release-package",
    "uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0 with: node-version: ${{ matrix.node-version }}",
    "run: curl -fsSL --proto '=https' --tlsv1.2 -o \"$RUNNER_TEMP/governed-npm.tgz\" \"https://registry.npmjs.org/npm/-/npm-${RAVEN_PINNED_NPM_VERSION}.tgz\"",
    "run: node ops/install-governed-npm.mjs --tarball \"$RUNNER_TEMP/governed-npm.tgz\" --dest \"$RUNNER_TEMP/governed-npm\"",
    "run: node ops/npm-version-gate.mjs --governed-npm \"$RUNNER_TEMP/governed-npm/package\"",
    "run: npm --prefix packages/verify-js ci",
    "run: node ops/verify-release-artifact.mjs \\ --pack-json \"$RUNNER_TEMP/release-package/pack.json\" \\ --tarball-dir \"$RUNNER_TEMP/release-package\" \\ --artifact-identity \"$RUNNER_TEMP/release-package/release-artifact-identity.json\" \\ --frozen-identity release/release-identity.json \\ --confirm-version \"${{ inputs.confirm_version }}\" \\ --release-ref \"${{ inputs.release_ref }}\" \\ --release-sha \"${{ inputs.release_sha }}\" \\ --release-tree \"${{ inputs.release_tree }}\"",
    "run: node ops/test-release-tarball.mjs \\ --pack-json \"$RUNNER_TEMP/release-package/pack.json\" \\ --tarball-dir \"$RUNNER_TEMP/release-package\" \\ --package-dir packages/verify-js"
  ],
  "publish": [
    "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 with: ref: ${{ inputs.release_sha }} fetch-depth: 0 persist-credentials: false",
    "env: RAVEN_RELEASE_REF: ${{ inputs.release_ref }} RAVEN_RELEASE_SHA: ${{ inputs.release_sha }} RAVEN_RELEASE_TREE: ${{ inputs.release_tree }} run: node ops/verify-release-ref.mjs",
    "uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0 with: path: ${{ runner.temp }}/release-package",
    "uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0 with: node-version: \"22.18.0\"",
    "run: curl -fsSL --proto '=https' --tlsv1.2 -o \"$RUNNER_TEMP/governed-npm.tgz\" \"https://registry.npmjs.org/npm/-/npm-${RAVEN_PINNED_NPM_VERSION}.tgz\"",
    "run: node ops/install-governed-npm.mjs --tarball \"$RUNNER_TEMP/governed-npm.tgz\" --dest \"$RUNNER_TEMP/governed-npm\"",
    "run: node ops/npm-version-gate.mjs --governed-npm \"$RUNNER_TEMP/governed-npm/package\"",
    "env: RAVEN_RELEASE_REF: ${{ inputs.release_ref }} RAVEN_RELEASE_SHA: ${{ inputs.release_sha }} RAVEN_RELEASE_TREE: ${{ inputs.release_tree }} run: node ops/publish-exact-release.mjs \\ --pack-json \"$RUNNER_TEMP/release-package/pack.json\" \\ --tarball-dir \"$RUNNER_TEMP/release-package\" \\ --artifact-identity \"$RUNNER_TEMP/release-package/release-artifact-identity.json\" \\ --frozen-identity release/release-identity.json \\ --confirm-version \"${{ inputs.confirm_version }}\" \\ --governed-npm \"$RUNNER_TEMP/governed-npm/package\"",
    "if: always() uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2 with: path: | ${{ runner.temp }}/release-package/raven-receipt-verifier-0.1.0.tgz ${{ runner.temp }}/release-package/pack.json ${{ runner.temp }}/release-package/release-artifact-identity.json release/release-identity.json"
  ]
};

export const GOVERNED_NODE_MATRIX = '["22.18.0", "24"]';
export const GOVERNED_PUBLISH_NODE = "22.18.0";

export const WORKFLOW_PATH = ".github/workflows/verify-js-publish.yml";
// sha256 of the exact reviewed workflow bytes. Any change to the file — even
// whitespace or a comment — is a reviewed change here.
export const WORKFLOW_SHA256 = "9b9944682007c899d41c55bad93f436cb284ff4693aec3d253362ee7356ca484";
// Whole-workflow shape (everything except steps), derived from the reviewed
// workflow with ops/publication-policy.mjs#parseWorkflowShape.
export const EXPECTED_WORKFLOW_SHAPE = {
  "topKeys": [
    "name",
    "on",
    "permissions",
    "env",
    "jobs"
  ],
  "blocks": {
    "name": "name: verify-js publish",
    "on": "on: workflow_dispatch: inputs: release_ref: description: \"Authorized protected source ref; policy currently permits refs/heads/main only\" required: true release_sha: description: \"Exact independently reviewed public mirror commit\" required: true release_tree: description: \"Exact independently reviewed public mirror tree\" required: true confirm_version: description: \"Package version; must be 0.1.0\" required: true",
    "permissions": "permissions: contents: read",
    "env": "env: RAVEN_PINNED_NPM_VERSION: \"11.18.0\""
  },
  "jobs": [
    {
      "name": "source-gate",
      "header": "name: Source and correspondence gates (secretless) runs-on: ubuntu-latest timeout-minutes: 20 permissions: contents: read strategy: fail-fast: false matrix: node-version: [\"22.18.0\", \"24\"]",
      "hasSteps": true
    },
    {
      "name": "package-artifact",
      "header": "name: Create the one release tarball (secretless) needs: source-gate runs-on: ubuntu-latest timeout-minutes: 20 permissions: contents: read",
      "hasSteps": true
    },
    {
      "name": "tarball-gate",
      "header": "name: Downloaded artifact customer gates needs: package-artifact runs-on: ubuntu-latest timeout-minutes: 20 permissions: contents: read strategy: fail-fast: false matrix: node-version: [\"22.18.0\", \"24\"]",
      "hasSteps": true
    },
    {
      "name": "publish",
      "header": "name: Protected atomic verification and publication needs: tarball-gate environment: npm-release runs-on: ubuntu-latest timeout-minutes: 20 permissions: contents: read id-token: write",
      "hasSteps": true
    }
  ]
};

// The governed npm CLI: the exact registry artifact for npm@11.18.0 bound by
// bytes. The publication boundary executes ONLY a tree that hashes to this
// identity, through the governed Node runtime by absolute path. Version
// strings printed by any program are never a trust anchor.
export const GOVERNED_NPM = {
  name: "npm",
  version: "11.18.0",
  tarballUrl: "https://registry.npmjs.org/npm/-/npm-11.18.0.tgz",
  tarballBytes: 2997746,
  tarballSha256: "73f6155215ebabf4ed96dca1f567c2372cc713c33af2e5b9b62fde4e92373e2e",
  tarballSha512: "4faecce0be70366d1c67b1012c4adc1246354a6cc45bf589f92003073b05518d547403df1475c542d67a4845e22b4fafcd7cac0af02c7a96cc6814f09eb003fb",
  tarballIntegrity: "sha512-T67M4L5wNm0cZ7EBLErcEkY1SmzEW/WJ+SADBzsFUY1UdAPfFHXFQtZ6SEXiK0+vzXysCvAsepbMaBTwnrAD+w==",
  registrySha1: "6ba3a51a3f2ef1eb51cca3289eceafcdef82f31c",
  fileCount: 1943,
  cliSha256: "8e5f6f3429f8cdbe693cdc29904e9d5a7b127a494bd15c804bd54c7403bfcbe7",
  treeSha256: "6600073ac88181666acb9428d2299588cfb933c557942a8e6a38a9fa07937e3f",
  nodeLines: /^v(?:22\.18\.0|24\.[0-9]+\.[0-9]+)$/,
};

// The publisher's environment is constructed, never inherited. Exactly these
// names may cross into the process that runs `npm publish`:
//   PATH        — replaced with the governed Node's bin directory plus the
//                 system tool directories npm needs (none for publish, kept
//                 minimal for git-less, script-less publish)
//   HOME        — replaced with a fresh private directory (no user npm config)
//   TMPDIR      — the wrapper's private temp root
//   GITHUB_ACTIONS, GITHUB_REPOSITORY, GITHUB_REPOSITORY_ID,
//   GITHUB_REPOSITORY_OWNER_ID, GITHUB_SERVER_URL, GITHUB_EVENT_NAME,
//   GITHUB_WORKFLOW_REF, GITHUB_SHA, GITHUB_REF, GITHUB_RUN_ID,
//   GITHUB_RUN_ATTEMPT — read by npm's provenance/sigstore CI context
//   ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN — the OIDC
//                 identity used for npm trusted publishing and provenance
//   RUNNER_ENVIRONMENT, RUNNER_ID, RUNNER_DESCRIPTION, RUNNER_TAGS,
//   RUNNER_EXECUTABLE_ARCH — runner metadata read by the provenance builder
// Everything else (NODE_OPTIONS, npm/NPM configuration, tokens, git
// configuration, proxies, CA overrides, locale, shell) is dropped.
export const PUBLISH_ENV_PASSTHROUGH = [
  "GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_REPOSITORY_OWNER_ID",
  "GITHUB_SERVER_URL", "GITHUB_EVENT_NAME", "GITHUB_WORKFLOW_REF", "GITHUB_SHA", "GITHUB_REF",
  "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
  "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  "RUNNER_ENVIRONMENT", "RUNNER_ID", "RUNNER_DESCRIPTION", "RUNNER_TAGS", "RUNNER_EXECUTABLE_ARCH",
];

// Presence of any of these in the inherited environment means the runner is
// not the reviewed environment: the wrapper refuses before publishing.
export const PUBLISH_ENV_FORBIDDEN = [
  /^NODE_OPTIONS$/, /^NODE_EXTRA_CA_CERTS$/, /^NODE_TLS_REJECT_UNAUTHORIZED$/,
  /^npm_config_/i, /^NPM_CONFIG_/, /^NPM_TOKEN$/, /^NODE_AUTH_TOKEN$/, /^NPM_ID_TOKEN$/, /^SIGSTORE_ID_TOKEN$/,
  /^GIT_CONFIG_/, /^GIT_DIR$/, /^GIT_WORK_TREE$/,
  /^(?:HTTPS?|ALL|NO)_PROXY$/i, /^SSL_CERT_(?:FILE|DIR)$/, /^XDG_CONFIG_HOME$/, /^PREFIX$/, /^NPM_PREFIX$/,
];
