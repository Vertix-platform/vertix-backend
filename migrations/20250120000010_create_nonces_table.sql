-- Create nonces table for wallet authentication
CREATE TABLE nonces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(42) NOT NULL,
    nonce VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_nonces_wallet_address ON nonces(wallet_address);
CREATE INDEX idx_nonces_nonce ON nonces(nonce);
CREATE INDEX idx_nonces_created_at ON nonces(created_at);

-- Create unique constraint to prevent duplicate nonces
CREATE UNIQUE INDEX idx_nonces_unique 
ON nonces(wallet_address, nonce);
