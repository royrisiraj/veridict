import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("EvidenceRegistryModule", (m) => {
  const registry = m.contract("EvidenceRegistry");
  return { registry };
});
