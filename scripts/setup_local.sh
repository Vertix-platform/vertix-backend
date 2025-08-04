#!/bin/bash

# Vertix Backend Local Development Setup Script
# This script helps set up the local development environment

set -e

echo "🚀 Setting up Vertix Backend for local development..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required tools are installed
check_requirements() {
    print_status "Checking requirements..."

    # Check if Rust is installed
    if ! command -v cargo &> /dev/null; then
        print_error "Rust is not installed. Please install Rust first: https://rustup.rs/"
        exit 1
    fi

    # Check if Foundry is installed
    if ! command -v forge &> /dev/null; then
        print_warning "Foundry is not installed. Installing Foundry..."
        curl -L https://foundry.paradigm.xyz | bash
        source ~/.bashrc
        foundryup
    fi

    # Check if Anvil is available
    if ! command -v anvil &> /dev/null; then
        print_error "Anvil is not available. Please install Foundry first."
        exit 1
    fi

    print_success "All requirements are met!"
}

# Build the contract extraction script
build_extraction_script() {
    print_status "Building contract extraction script..."

    cd scripts
    if [ -f "Cargo.toml" ]; then
        cargo build --release
        print_success "Contract extraction script built successfully!"
    else
        print_error "Contract extraction script not found!"
        exit 1
    fi
    cd ..
}

# Deploy contracts to local Anvil
deploy_contracts() {
    print_status "Deploying contracts to local Anvil..."

    # Check if contracts directory exists
    if [ ! -d "../contracts" ]; then
        print_error "Contracts directory not found! Make sure you're in the right directory."
        exit 1
    fi

    cd ../contracts

    # Build contracts
    print_status "Building contracts..."
    forge build

    # Start Anvil in background
    print_status "Starting Anvil..."
    anvil --port 8545 --chain-id 31337 &
    ANVIL_PID=$!

    # Wait for Anvil to start
    sleep 3

    # Deploy contracts
    print_status "Deploying contracts..."
    forge script script/DeployVertix.s.sol:DeployVertix --rpc-url http://localhost:8545 --broadcast --verify

    # Stop Anvil
    kill $ANVIL_PID

    print_success "Contracts deployed successfully!"
    cd ../vertix-backend
}

# Extract ABIs and addresses
extract_contract_data() {
    print_status "Extracting contract ABIs and addresses..."

    if [ -f "scripts/Cargo.toml" ]; then
        cd scripts
        cargo run --release
        cd ..
        print_success "Contract data extracted successfully!"
    else
        print_error "Contract extraction script not found!"
        exit 1
    fi
}

# Create environment file
create_env_file() {
    print_status "Creating environment file..."

    if [ ! -f ".env" ]; then
        cat > .env << EOF
# Database Configuration
DATABASE_URL=postgresql://postgres:password@localhost:5432/vertix_db

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRATION=24h

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Blockchain Configuration
RPC_URL=http://localhost:8545
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
CHAIN_ID=31337

# Redis Configuration
REDIS_URL=redis://localhost:6379

# Server Configuration
PORT=3000
HOST=0.0.0.0
EOF
        print_success "Environment file created!"
    else
        print_warning "Environment file already exists. Skipping..."
    fi
}

# Install dependencies
install_dependencies() {
    print_status "Installing Rust dependencies..."
    cargo build
    print_success "Dependencies installed successfully!"
}

# Main execution
main() {
    print_status "Starting Vertix Backend setup..."

    check_requirements
    build_extraction_script
    deploy_contracts
    extract_contract_data
    create_env_file
    install_dependencies

    print_success "Setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Update the .env file with your actual configuration"
    echo "2. Start your database (PostgreSQL)"
    echo "3. Start Redis"
    echo "4. Run: cargo run"
    echo ""
    echo "To start Anvil for testing:"
    echo "anvil --port 8545 --chain-id 31337"
    echo ""
    echo "To run tests:"
    echo "cargo test"
}

# Run main function
main "$@"