import { spawn } from "node:child_process";
import { resolve } from "node:path";
const cwd = resolve("../backend");
const executable = resolve(cwd, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const child = spawn(executable, ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"], {
  cwd, stdio: "inherit", env: { ...process.env, CHAIN_MODE: "fixture", LIVE_CHECKS: "false", OPENAI_API_KEY: "", OPENAI_MODEL: "", GOOGLE_SAFE_BROWSING_KEY: "", DATABASE_PATH: resolve("../runtime/browser-tests.db") },
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
child.on("exit", (code) => process.exit(code ?? 0));
