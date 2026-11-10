import { expect } from "chai";
import { network } from "hardhat";
import { readFileSync } from "node:fs";

const { ethers } = await network.connect();

describe("EvidenceRegistry", function () {
  const REPORT_ID = ethers.keccak256(ethers.toUtf8Bytes("report:suspicious-1"));
  const MERKLE_ROOT = ethers.keccak256(ethers.toUtf8Bytes("sample-merkle-root"));
  const TAMPERED_ROOT = ethers.keccak256(ethers.toUtf8Bytes("tampered-merkle-root"));
  const SCHEMA_HASH = ethers.keccak256(ethers.toUtf8Bytes("sealed-evidence/1"));
  const ZERO_BYTES32 = ethers.ZeroHash;

  it("registers a new report root and emits Registered", async function () {
    const Registry = await ethers.getContractFactory("EvidenceRegistry");
    const registry = await Registry.deploy();

    await expect(registry.register(REPORT_ID, MERKLE_ROOT, SCHEMA_HASH))
      .to.emit(registry, "Registered");

    const record = await registry.reports(REPORT_ID);
    expect(record.root).to.equal(MERKLE_ROOT);
    expect(record.schemaHash).to.equal(SCHEMA_HASH);
    expect(record.timestamp).to.be.greaterThan(0n);

    expect(await registry.verifyRoot(REPORT_ID, MERKLE_ROOT)).to.equal(true);
    expect(await registry.verifyRoot(REPORT_ID, TAMPERED_ROOT)).to.equal(false);
  });

  it("reverts when registering a duplicate reportId", async function () {
    const Registry = await ethers.getContractFactory("EvidenceRegistry");
    const registry = await Registry.deploy();

    await registry.register(REPORT_ID, MERKLE_ROOT, SCHEMA_HASH);
    await expect(
      registry.register(REPORT_ID, MERKLE_ROOT, SCHEMA_HASH)
    ).to.be.revertedWithCustomError(registry, "ReportAlreadyExists");
  });

  it("reverts when registering an empty zero Merkle root", async function () {
    const Registry = await ethers.getContractFactory("EvidenceRegistry");
    const registry = await Registry.deploy();

    await expect(
      registry.register(REPORT_ID, ZERO_BYTES32, SCHEMA_HASH)
    ).to.be.revertedWithCustomError(registry, "InvalidRoot");
  });

  it("does not verify an unknown report", async function () {
    const registry = await ethers.deployContract("EvidenceRegistry");
    expect(await registry.verifyRoot(REPORT_ID, MERKLE_ROOT)).to.equal(false);
  });

  it("emits the exact stored registration fields", async function () {
    const registry = await ethers.deployContract("EvidenceRegistry");
    const tx = await registry.register(REPORT_ID, MERKLE_ROOT, SCHEMA_HASH);
    const receipt = await tx.wait();
    const block = await ethers.provider.getBlock(receipt!.blockNumber);
    await expect(tx).to.emit(registry, "Registered")
      .withArgs(REPORT_ID, MERKLE_ROOT, SCHEMA_HASH, BigInt(block!.timestamp));
  });

  it("verifies Python canonical leaves and odd/even proofs with OpenZeppelin", async function () {
    const harness = await ethers.deployContract("MerkleProofHarness");
    const vectors = JSON.parse(readFileSync(new URL("./merkle-vectors.json", import.meta.url), "utf8"));
    for (const vector of vectors) {
      for (let index = 0; index < vector.leaves.length; index++) {
        const item = vector.leaves[index];
        const typed = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "bytes32"], [ethers.id(item.type), ethers.keccak256(ethers.toUtf8Bytes(item.canonical))],
        ));
        expect(typed).to.equal(item.hash);
        expect(await harness.verify(vector.proofs[index], vector.root, typed)).to.equal(true);
        expect(await harness.verify(vector.proofs[index], vector.root, ethers.ZeroHash)).to.equal(false);
      }
    }
  });
});
