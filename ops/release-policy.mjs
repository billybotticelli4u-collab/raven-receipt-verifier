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
