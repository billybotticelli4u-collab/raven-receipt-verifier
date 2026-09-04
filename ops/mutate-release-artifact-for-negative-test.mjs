// Creates disposable, intentionally invalid release-artifact variants for
// non-vacuity checks. This script is never used by the publish workflow.
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  parseArgs,
  readJson,
  resolveTarballPath,
  run,
} from "./release-artifact-utils.mjs";

const args = parseArgs(process.argv);
const mutation = args.mutation;
const sourcePackJson = path.resolve(args["pack-json"]);
const sourceTarballDir = path.resolve(args["tarball-dir"]);
const outDir = path.resolve(args.out);
const { packed, tarball } = resolveTarballPath({
  packJsonPath: sourcePackJson,
  tarballDir: sourceTarballDir,
});
const scratch = mkdtempSync(path.join(tmpdir(), "raven-artifact-mutant-"));

mkdirSync(outDir, { recursive: true });
copyFileSync(sourcePackJson, path.join(outDir, "pack.json"));

try {
  if (mutation === "altered-pack-json") {
    const packJson = readJson(path.join(outDir, "pack.json"));
    packJson[0].size += 1;
    writeFileSync(path.join(outDir, "pack.json"), `${JSON.stringify(packJson, null, 2)}\n`, "utf8");
    copyFileSync(tarball, path.join(outDir, packed.filename));
  } else {
    run("tar", ["-xzf", tarball, "-C", scratch]);
    const packageRoot = path.join(scratch, "package");
    const manifestPath = path.join(packageRoot, "package.json");
    const manifest = readJson(manifestPath);

    if (mutation === "unexpected-packaged-file") {
      writeFileSync(path.join(packageRoot, "dist/proposed.js"), "export const proposed = true;\n", "utf8");
    } else if (mutation === "runtime-dependency") {
      manifest.dependencies = { ...(manifest.dependencies ?? {}), "left-pad": "1.3.0" };
      writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    } else if (mutation === "withheld-export") {
      writeFileSync(path.join(packageRoot, "dist/proposed.js"), "export const proposed = true;\n", "utf8");
      manifest.exports = {
        ...(manifest.exports ?? {}),
        "./proposed": "./dist/proposed.js",
      };
      writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    } else {
      throw new Error(`unknown mutation: ${mutation}`);
    }

    run("tar", ["-czf", path.join(outDir, packed.filename), "-C", scratch, "package"]);
  }

  console.log(`wrote ${mutation} mutant artifact to ${outDir}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
