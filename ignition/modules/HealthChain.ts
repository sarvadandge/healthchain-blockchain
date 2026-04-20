import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

/**
 * Deploys the merged HealthChain contract.
 *
 * Deploy command:
 *   npx hardhat ignition deploy ignition/modules/HealthChain.ts --network polygonAmoy
 *
 * Reset (if redeploying):
 *   npx hardhat ignition deploy ignition/modules/HealthChain.ts --network polygonAmoy --reset
 */
const HealthChainModule = buildModule("HealthChainModule", (m) => {
  const healthChain = m.contract("HealthChain");
  return { healthChain };
});

export default HealthChainModule;
