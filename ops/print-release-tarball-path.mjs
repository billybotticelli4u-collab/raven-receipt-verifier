import path from "node:path";
import { parseArgs, resolveTarballPath } from "./release-artifact-utils.mjs";

const args = parseArgs(process.argv);
const { tarball } = resolveTarballPath({
  packJsonPath: path.resolve(args["pack-json"]),
  tarballDir: path.resolve(args["tarball-dir"]),
});

console.log(tarball);
