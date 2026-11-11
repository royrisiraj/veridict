import { network } from "hardhat";
import { mkdir, writeFile, access } from "node:fs/promises";
import { dirname } from "node:path";

async function main() {
// This guard is deliberate: compilation/tests never broadcast a deployment.
if (process.env.CONFIRM_SEPOLIA_DEPLOY !== "11155111") throw new Error("Set CONFIRM_SEPOLIA_DEPLOY=11155111 only after deployment approval.");
const destination = process.env.SEPOLIA_DEPLOYMENT_PATH ?? "../runtime/sepolia-deployment.json";
let existing = false;
try { await access(destination); existing = true; } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
if (existing) throw new Error("Deployment manifest already exists; inspect it before creating another registry.");
const { ethers } = await network.create();
if ((await ethers.provider.getNetwork()).chainId !== 11155111n) throw new Error("Refusing deployment outside Ethereum Sepolia.");
const [deployer] = await ethers.getSigners();
const balance = await ethers.provider.getBalance(deployer.address);
if (balance === 0n) throw new Error("The dedicated Sepolia account needs test ETH.");
const factory = await ethers.getContractFactory("EvidenceRegistry");
const unsigned = await factory.getDeployTransaction();
const gas = await ethers.provider.estimateGas({ ...unsigned, from: deployer.address });
const fee = await ethers.provider.getFeeData();
const gasLimit = (gas * 120n + 99n) / 100n;
const gasPrice = fee.gasPrice ?? 0n;
const maxCost = gasLimit * gasPrice;
if (!maxCost || balance < maxCost || maxCost > ethers.parseEther(process.env.MAX_DEPLOY_ETH ?? "0.02")) throw new Error("Deployment exceeds wallet balance or MAX_DEPLOY_ETH budget.");
const registry = await factory.deploy({ gasLimit, gasPrice });
const transaction = registry.deploymentTransaction();
if (!transaction) throw new Error("No deployment transaction was returned.");
const receipt = await transaction.wait(2);
if (!receipt || receipt.status !== 1) throw new Error("Deployment was not confirmed successfully.");
const address = await registry.getAddress();
if (await ethers.provider.getCode(address) === "0x") throw new Error("Deployed bytecode is missing.");
if (await registry.verifyRoot(ethers.ZeroHash, ethers.ZeroHash)) throw new Error("Registry sanity check failed.");
const block = await ethers.provider.getBlock(receipt.blockNumber);
if (!block) throw new Error("Deployment block unavailable.");
const manifest = {
  network: "Ethereum Sepolia", chain_id: 11155111, contract_address: address,
  tx_hash: receipt.hash, block_number: receipt.blockNumber,
  abi_reference: "contracts/artifacts/contracts/EvidenceRegistry.sol/EvidenceRegistry.json",
  deployed_at: new Date(block.timestamp * 1000).toISOString(),
  explorer_url: `https://sepolia.etherscan.io/tx/${receipt.hash}`, bytecode_confirmed: true,
};
await mkdir(dirname(destination), { recursive: true });
await writeFile(destination, JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
console.log(JSON.stringify(manifest, null, 2));
}

await main().catch(() => { console.error("Sepolia deployment did not complete. Check approval, credentials and pending transactions privately; no deployment success is asserted."); process.exitCode = 1; });
