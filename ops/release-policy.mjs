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
    "run: npm install --global \"npm@${RAVEN_PINNED_NPM_VERSION}\"",
    "run: node ops/npm-version-gate.mjs \"${RAVEN_PINNED_NPM_VERSION}\"",
    "run: npm --prefix packages/verify-js ci",
    "run: npm --prefix packages/verify-js run build",
    "run: node ops/verify-byte-correspondence.mjs",
    "run: npm --prefix packages/verify-js test",
    "run: node --test ops/*.test.mjs"
  ],
  "package-artifact": [
    "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 with: ref: ${{ inputs.release_sha }} fetch-depth: 0 persist-credentials: false",
    "env: RAVEN_RELEASE_REF: ${{ inputs.release_ref }} RAVEN_RELEASE_SHA: ${{ inputs.release_sha }} RAVEN_RELEASE_TREE: ${{ inputs.release_tree }} run: node ops/verify-release-ref.mjs",
    "uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0 with: node-version: \"22.18.0\"",
    "run: npm install --global \"npm@${RAVEN_PINNED_NPM_VERSION}\"",
    "run: node ops/npm-version-gate.mjs \"${RAVEN_PINNED_NPM_VERSION}\"",
    "run: npm --prefix packages/verify-js ci",
    "run: set -euo pipefail mkdir -p \"$RUNNER_TEMP/release-package\" cd packages/verify-js npm pack --json --pack-destination \"$RUNNER_TEMP/release-package\" > \"$RUNNER_TEMP/release-package/pack.json\"",
    "env: GITHUB_REF: ${{ inputs.release_ref }} run: node ops/create-release-artifact-identity.mjs \\ --pack-json \"$RUNNER_TEMP/release-package/pack.json\" \\ --tarball-dir \"$RUNNER_TEMP/release-package\" \\ --out \"$RUNNER_TEMP/release-package/release-artifact-identity.json\" \\ --release-ref \"${{ inputs.release_ref }}\"",
    "run: node ops/verify-release-artifact.mjs \\ --pack-json \"$RUNNER_TEMP/release-package/pack.json\" \\ --tarball-dir \"$RUNNER_TEMP/release-package\" \\ --artifact-identity \"$RUNNER_TEMP/release-package/release-artifact-identity.json\" \\ --frozen-identity release/release-identity.json \\ --confirm-version \"${{ inputs.confirm_version }}\" \\ --release-ref \"${{ inputs.release_ref }}\" \\ --release-sha \"${{ inputs.release_sha }}\" \\ --release-tree \"${{ inputs.release_tree }}\"",
    "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2 with: path: | ${{ runner.temp }}/release-package/raven-receipt-verifier-0.1.0.tgz ${{ runner.temp }}/release-package/pack.json ${{ runner.temp }}/release-package/release-artifact-identity.json if-no-files-found: error"
  ],
  "tarball-gate": [
    "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 with: ref: ${{ inputs.release_sha }} fetch-depth: 0 persist-credentials: false",
    "env: RAVEN_RELEASE_REF: ${{ inputs.release_ref }} RAVEN_RELEASE_SHA: ${{ inputs.release_sha }} RAVEN_RELEASE_TREE: ${{ inputs.release_tree }} run: node ops/verify-release-ref.mjs",
    "uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0 with: path: ${{ runner.temp }}/release-package",
    "uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0 with: node-version: ${{ matrix.node-version }}",
    "run: npm install --global \"npm@${RAVEN_PINNED_NPM_VERSION}\"",
    "run: node ops/npm-version-gate.mjs \"${RAVEN_PINNED_NPM_VERSION}\"",
    "run: npm --prefix packages/verify-js ci",
    "run: node ops/verify-release-artifact.mjs \\ --pack-json \"$RUNNER_TEMP/release-package/pack.json\" \\ --tarball-dir \"$RUNNER_TEMP/release-package\" \\ --artifact-identity \"$RUNNER_TEMP/release-package/release-artifact-identity.json\" \\ --frozen-identity release/release-identity.json \\ --confirm-version \"${{ inputs.confirm_version }}\" \\ --release-ref \"${{ inputs.release_ref }}\" \\ --release-sha \"${{ inputs.release_sha }}\" \\ --release-tree \"${{ inputs.release_tree }}\"",
    "run: node ops/test-release-tarball.mjs \\ --pack-json \"$RUNNER_TEMP/release-package/pack.json\" \\ --tarball-dir \"$RUNNER_TEMP/release-package\" \\ --package-dir packages/verify-js"
  ],
  "publish": [
    "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 with: ref: ${{ inputs.release_sha }} fetch-depth: 0 persist-credentials: false",
    "env: RAVEN_RELEASE_REF: ${{ inputs.release_ref }} RAVEN_RELEASE_SHA: ${{ inputs.release_sha }} RAVEN_RELEASE_TREE: ${{ inputs.release_tree }} run: node ops/verify-release-ref.mjs",
    "uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0 with: path: ${{ runner.temp }}/release-package",
    "uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0 with: node-version: \"22.18.0\" registry-url: \"https://registry.npmjs.org\"",
    "run: npm install --global \"npm@${RAVEN_PINNED_NPM_VERSION}\"",
    "run: node ops/npm-version-gate.mjs \"${RAVEN_PINNED_NPM_VERSION}\"",
    "env: RAVEN_RELEASE_REF: ${{ inputs.release_ref }} RAVEN_RELEASE_SHA: ${{ inputs.release_sha }} RAVEN_RELEASE_TREE: ${{ inputs.release_tree }} run: node ops/publish-exact-release.mjs \\ --pack-json \"$RUNNER_TEMP/release-package/pack.json\" \\ --tarball-dir \"$RUNNER_TEMP/release-package\" \\ --artifact-identity \"$RUNNER_TEMP/release-package/release-artifact-identity.json\" \\ --frozen-identity release/release-identity.json \\ --confirm-version \"${{ inputs.confirm_version }}\"",
    "if: always() uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2 with: path: | ${{ runner.temp }}/release-package/raven-receipt-verifier-0.1.0.tgz ${{ runner.temp }}/release-package/pack.json ${{ runner.temp }}/release-package/release-artifact-identity.json release/release-identity.json"
  ]
};

export const GOVERNED_NODE_MATRIX = '["22.18.0", "24"]';
export const GOVERNED_PUBLISH_NODE = "22.18.0";
