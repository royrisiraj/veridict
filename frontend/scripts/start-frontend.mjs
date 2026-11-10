import { cpSync, mkdirSync } from "node:fs";
import { spawn } from "node:child_process";
mkdirSync(".next/standalone/.next", { recursive: true });
cpSync(".next/static", ".next/standalone/.next/static", { recursive: true });
const child = spawn(process.execPath, [".next/standalone/server.js"], {
  stdio: "inherit", env: { ...process.env, BACKEND_BASE_URL: process.env.BACKEND_BASE_URL || process.env.BACKEND_URL || "http://127.0.0.1:8000", HOSTNAME: "127.0.0.1", PORT: "3000" },
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
child.on("exit", (code) => process.exit(code ?? 0));
