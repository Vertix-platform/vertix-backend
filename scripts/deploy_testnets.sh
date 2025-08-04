#!/bin/bash

# Deploy Vertix contracts to testnets
# This script deploys to Base Sepolia and Polygon Mumbai

set -e

echo "🚀 Deploying Vertix contracts to testnets..."

# Check if required environment variables are set
if [ -z "$PRIVATE_KEY" ]; then
    echo "❌ PRIVATE_KEY environment variable is required"
    exit 1
fi

# Deploy to Base Sepolia
echo "🌐 Deploying to Base Sepolia..."
cd ../../contracts
forge script script/DeployVertix.s.sol:DeployVertix \
    --rpc-url https://sepolia.base.org \
    --broadcast \
    --chain-id 84532

# Deploy to Polygon Mumbai
echo "🌐 Deploying to Polygon Mumbai..."
forge script script/DeployVertix.s.sol:DeployVertix \
    --rpc-url https://polygon-mumbai-bor.publicnode.com \
    --broadcast \
    --chain-id 80001

echo "✅ Deployment to testnets complete!"
echo "📁 Check the broadcast/ directory for deployment artifacts"

# #[cfg(feature = "anvil")]
# use crate::infrastructure::contracts::addresses::addresses_anvil::*;

# #[cfg(feature = "base_sepolia")]
# use crate::infrastructure::contracts::addresses::addresses_base_sepolia::*;

# #[cfg(feature = "polygon_mumbai")]
# use crate::infrastructure::contracts::addresses::addresses_polygon_mumbai::*;