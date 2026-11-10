import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
const output = "lib/api.generated.ts";
const before = readFileSync(output, "utf8");
const run = spawnSync(process.execPath, ["node_modules/openapi-typescript/bin/cli.js", "openapi.json", "-o", output], { stdio: "inherit" });
if (run.status !== 0) process.exit(run.status ?? 1);
if (before !== readFileSync(output, "utf8")) {
  console.error("Type contract drift: regenerate and commit lib/api.generated.ts");
  process.exit(1);
}
