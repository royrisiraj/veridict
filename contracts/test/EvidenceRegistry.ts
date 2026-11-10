import { expect } from "chai";
import { ethers } from "hardhat";

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
});
