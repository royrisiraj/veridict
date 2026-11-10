import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers],
  solidity: {
    version: "0.8.38",
    path: require.resolve("solc/soljson.js"),
    settings: { evmVersion: "cancun" },
  },
  networks: {
    localhost: { type: "http", chainType: "l1", url: process.env.RPC_URL ?? "http://127.0.0.1:8545" },
  },
});
