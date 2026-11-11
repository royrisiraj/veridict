import { network } from "hardhat";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

async function main() {
if (process.env.CONFIRM_SEPOLIA_ANCHOR !== "11155111") throw new Error("Set CONFIRM_SEPOLIA_ANCHOR=11155111 only after fixture-registration approval.");
const root = fileURLToPath(new URL("../../", import.meta.url));
const python = process.env.PYTHON_EXECUTABLE ?? fileURLToPath(new URL(process.platform === "win32" ? "../../backend/.venv/Scripts/python.exe" : "../../backend/.venv/bin/python", import.meta.url));
// Reuse the exact canonical Python implementation, and independently verify it below in Ethers.
const checked = JSON.parse(execFileSync(python, [root + "backend/scripts/check_passports.py"], { encoding: "utf8" }));
const { ethers } = await network.create();
if ((await ethers.provider.getNetwork()).chainId !== 11155111n) throw new Error("Sepolia chain ID mismatch.");
const deployment = JSON.parse(await readFile(process.env.SEPOLIA_DEPLOYMENT_PATH ?? "../runtime/sepolia-deployment.json", "utf8"));
if (deployment.chain_id !== 11155111 || await ethers.provider.getCode(deployment.contract_address) === "0x") throw new Error("Sepolia deployment/bytecode unavailable.");
const registry = await ethers.getContractAt("EvidenceRegistry", deployment.contract_address);
const schema = ethers.id("sealed-evidence/1");
const output = process.env.FIXTURE_ANCHOR_MANIFEST ?? "../runtime/sepolia-fixtures.json";
let manifest: Record<string, unknown> = {};
try { manifest = JSON.parse(await readFile(output, "utf8")); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
// Preflight EVERY report before any transaction: a later conflict must not produce partial registrations.
for (const item of checked) {
  if (item.schema_hash !== schema) throw new Error("Schema hash mismatch.");
  for (const leaf of item.leaves) {
    const expected = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32"], [ethers.id(leaf.type), ethers.keccak256(ethers.toUtf8Bytes(leaf.canonical))]));
    if (expected !== leaf.hash) throw new Error(`Leaf parity failure: ${leaf.id}`);
    let folded = expected;
    for (const sibling of item.proofs_by_id[leaf.id]) folded = ethers.keccak256(ethers.concat([folded, sibling].sort()));
    if (folded !== item.root) throw new Error(`Inclusion proof failure: ${leaf.id}`);
  }
  const record = await registry.reports(item.report_id);
  if (record.timestamp !== 0n && (record.root !== item.root || record.schemaHash !== schema)) throw new Error(`CONFLICT: ${item.report_id}; no registrations submitted.`);
}
const [signer] = await ethers.getSigners();
let spentBudget = 0n;
for (const item of checked) {
  let record = await registry.reports(item.report_id);
  let txHash: string | null = null;
  let blockNumber: number | null = null;
  if (record.timestamp === 0n) {
    const gas = await registry.register.estimateGas(item.report_id, item.root, schema);
    const fee = await ethers.provider.getFeeData();
    const gasLimit = (gas * 120n + 99n) / 100n;
    const gasPrice = fee.gasPrice ?? 0n;
    const cost = gasLimit * gasPrice;
    spentBudget += cost;
    if (!cost || spentBudget > ethers.parseEther(process.env.MAX_FIXTURE_ANCHOR_ETH ?? "0.02") || await ethers.provider.getBalance(signer.address) < cost) throw new Error("Fixture registration budget/balance exceeded.");
    const tx = await registry.register(item.report_id, item.root, schema, { gasLimit, gasPrice });
    const receipt = await tx.wait(2);
    if (!receipt || receipt.status !== 1) throw new Error("Fixture transaction not confirmed.");
    txHash = receipt.hash; blockNumber = receipt.blockNumber;
    record = await registry.reports(item.report_id);
  } else {
    const events = await registry.queryFilter(registry.filters.Registered(item.report_id), deployment.block_number, "latest");
    if (!events.length) throw new Error("Existing root matches but registration transaction metadata could not be retrieved.");
    txHash = events[0].transactionHash; blockNumber = events[0].blockNumber;
  }
  if (record.root !== item.root || record.schemaHash !== schema || record.timestamp === 0n) throw new Error("Independent root readback failed.");
  manifest[item.report_id] = { report_id: item.report_id, root: item.root, schema_hash: schema, tx_hash: txHash, block_number: blockNumber, contract_address: deployment.contract_address, network: "evm:11155111", mode: "evm" };
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`${item.report_id}: root confirmed; transaction ${txHash}`);
}
}

await main().catch(() => { console.error("Fixture anchoring did not complete. Check conflicts, approval and provider configuration privately; completed entries remain in the manifest."); process.exitCode = 1; });
