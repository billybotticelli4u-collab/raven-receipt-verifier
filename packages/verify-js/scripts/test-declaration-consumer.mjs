import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageDir = fileURLToPath(new URL("..", import.meta.url));
const repositoryRoot = path.resolve(packageDir, "../..");
const scratch = mkdtempSync(
  path.join(tmpdir(), "raven-receipt-verifier-declarations-"),
);
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
// Prefer the package-local compiler installed from this package's own lock
// (`npm ci` in packages/verify-js), so the gate is standalone in a
// package-only checkout. Fall back to the workspace-root install when the
// package dependencies are hoisted there (root `npm ci` in the monorepo).
const tscCandidates = [
  path.join(packageDir, "node_modules", "typescript", "bin", "tsc"),
  path.join(repositoryRoot, "node_modules", "typescript", "bin", "tsc"),
];
const tsc = tscCandidates.find((candidate) => existsSync(candidate));
if (!tsc) {
  throw new Error(
    `typescript not found; looked in: ${tscCandidates.join(", ")}`,
  );
}

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...options,
  });
  if (result.status !== 0) {
    process.stdout.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`${command} ${args.join(" ")} exited ${result.status}`);
  }
  return result;
};

try {
  const packed = run(
    npm,
    ["pack", "--json", "--pack-destination", scratch],
    { cwd: packageDir },
  );
  const packResult = JSON.parse(packed.stdout);
  const tarball = path.join(scratch, packResult[0].filename);

  run(npm, ["init", "--yes"], { cwd: scratch });
  run(
    npm,
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--offline",
      tarball,
    ],
    { cwd: scratch },
  );

  writeFileSync(
    path.join(scratch, "consumer.ts"),
    `import {
  RAVEN_PRODUCTION_TRUST_ANCHOR,
  ravenProductionTrustedKeys,
  verifyReceiptV1,
  verifyReceiptV1ForSubject,
  type ExpectedSolanaReceiptSubject,
  type RavenTrustAnchorKey,
  type VerifyReceiptForSubjectResult,
} from "raven-receipt-verifier";

const result = verifyReceiptV1({}, { now: "2026-01-01T00:00:00.000Z" });
const valid: boolean = result.valid;
const reasons: string[] = result.reasons;
void valid;
void reasons;
const anchors: readonly RavenTrustAnchorKey[] = RAVEN_PRODUCTION_TRUST_ANCHOR;
const keys: Set<string> = ravenProductionTrustedKeys();
void anchors;
void keys;

const subject: ExpectedSolanaReceiptSubject = {
  chain: "solana-mainnet",
  mintAddress: "So11111111111111111111111111111111111111112",
  tokenProgramAddress: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
};
const bound: VerifyReceiptForSubjectResult = verifyReceiptV1ForSubject(
  {},
  subject,
  { allowUntrustedKey: true },
);
const subjectMatches: boolean | null = bound.subjectMatches;
const subjectReasons: string[] = bound.subjectReasons;
const keyTrusted: boolean | undefined = bound.keyTrusted;
void subjectMatches;
void subjectReasons;
void keyTrusted;
`,
    "utf8",
  );
  writeFileSync(
    path.join(scratch, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          target: "ES2022",
          module: "NodeNext",
          moduleResolution: "NodeNext",
          strict: true,
          noEmit: true,
          skipLibCheck: true,
          types: [],
        },
        include: ["consumer.ts"],
      },
      null,
      2,
    ),
    "utf8",
  );

  run(process.execPath, [tsc, "-p", "tsconfig.json"], { cwd: scratch });
  const installed = JSON.parse(
    readFileSync(
      path.join(
        scratch,
        "node_modules",
        "raven-receipt-verifier",
        "package.json",
      ),
      "utf8",
    ),
  );
  console.log(
    `declaration consumer compiled against ${installed.exports["."].types}`,
  );
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
