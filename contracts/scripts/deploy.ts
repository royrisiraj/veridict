import { network } from "hardhat";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const { ethers } = await network.connect();
const registry = await ethers.deployContract("EvidenceRegistry");
await registry.waitForDeployment();
const destination = process.env.DEPLOYMENT_PATH ?? "../runtime/deployment.json";
await mkdir(dirname(destination), { recursive: true });
await writeFile(destination, JSON.stringify({
  contract_address: await registry.getAddress(), chain_id: Number((await ethers.provider.getNetwork()).chainId),
}, null, 2));
console.log(`EvidenceRegistry deployed: ${await registry.getAddress()}`);
