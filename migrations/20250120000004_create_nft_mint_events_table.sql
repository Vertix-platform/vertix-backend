-- Create NFT mint events table for blockchain events
CREATE TABLE nft_mint_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    to_address VARCHAR(42) NOT NULL,
    token_id BIGINT NOT NULL,
    collection_id BIGINT,
    transaction_hash VARCHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    chain_id BIGINT NOT NULL DEFAULT 84532,
    metadata_hash VARCHAR(66),
    token_uri TEXT,
    royalty_bps BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_nft_mint_events_to_address ON nft_mint_events(to_address);
CREATE INDEX idx_nft_mint_events_token_id ON nft_mint_events(token_id);
CREATE INDEX idx_nft_mint_events_collection_id ON nft_mint_events(collection_id);
CREATE INDEX idx_nft_mint_events_chain_id ON nft_mint_events(chain_id);
CREATE INDEX idx_nft_mint_events_block_number ON nft_mint_events(block_number);

-- Create unique constraint to prevent duplicate events
CREATE UNIQUE INDEX idx_nft_mint_events_unique 
ON nft_mint_events(transaction_hash, token_id, chain_id);
