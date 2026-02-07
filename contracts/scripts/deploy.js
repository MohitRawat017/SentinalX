const hre = require("hardhat");

async function main() {
  console.log("🛡️  Deploying SentinelX AuditProofBatch contract...");

  const AuditProofBatch = await hre.ethers.getContractFactory("AuditProofBatch");
  const contract = await AuditProofBatch.deploy();

  await contract.waitForDeployment();
  const address = await contract.getAddress();

  console.log(`✅ AuditProofBatch deployed to: ${address}`);
  console.log(`🔗 Etherscan: https://sepolia.etherscan.io/address/${address}`);
  console.log(`\nUpdate your .env file:`);
  console.log(`AUDIT_CONTRACT_ADDRESS=${address}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
