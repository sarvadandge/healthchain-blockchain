#!/bin/sh
set -e

echo "Deploying..."

echo y | npx hardhat ignition deploy ./ignition/modules/HealthChain.ts --network polygonAmoy

echo "Exporting ABI and address..."

mkdir -p /shared

# Copy ABI
cp artifacts/contracts/HealthChain.sol/HealthChain.json /shared/HealthChain.json

# Install jq
apk add --no-cache jq

CHAIN_ID=80002

ADDRESS=$(jq -r ".\"HealthChainModule#HealthChain\"" \
  ignition/deployments/chain-$CHAIN_ID/deployed_addresses.json)

echo $ADDRESS > /shared/address.txt

echo "Contract deployed at: $ADDRESS"

echo "Done"