-- Create NFT delisting events table for blockchain events
CREATE TABLE nft_delisting_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    listing_id BIGINT NOT NULL,
    seller_address VARCHAR(42) NOT NULL,
    nft_contract VARCHAR(42) NOT NULL,
    token_id BIGINT NOT NULL,
    is_nft BOOLEAN NOT NULL DEFAULT TRUE,
    transaction_hash VARCHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_nft_delisting_events_chain_id ON nft_delisting_events(chain_id);
CREATE INDEX idx_nft_delisting_events_listing_id ON nft_delisting_events(listing_id);
CREATE INDEX idx_nft_delisting_events_seller ON nft_delisting_events(seller_address);
CREATE INDEX idx_nft_delisting_events_nft_contract ON nft_delisting_events(nft_contract);
CREATE INDEX idx_nft_delisting_events_token_id ON nft_delisting_events(token_id);
CREATE INDEX idx_nft_delisting_events_block_number ON nft_delisting_events(block_number);

-- Create unique constraint to prevent duplicate events
CREATE UNIQUE INDEX idx_nft_delisting_events_unique 
ON nft_delisting_events(transaction_hash, listing_id, chain_id);
