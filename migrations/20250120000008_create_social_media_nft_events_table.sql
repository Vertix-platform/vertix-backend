-- Create social media NFT events table for blockchain events
CREATE TABLE social_media_nft_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    to_address VARCHAR(42) NOT NULL,
    token_id BIGINT NOT NULL,
    social_media_id VARCHAR(255) NOT NULL,
    token_uri TEXT,
    metadata_hash VARCHAR(66),
    signature VARCHAR(255) NOT NULL,
    royalty_recipient VARCHAR(42),
    royalty_bps BIGINT,
    transaction_hash VARCHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    chain_id BIGINT NOT NULL DEFAULT 84532,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_social_media_nft_events_to_address ON social_media_nft_events(to_address);
CREATE INDEX idx_social_media_nft_events_token_id ON social_media_nft_events(token_id);
CREATE INDEX idx_social_media_nft_events_social_media_id ON social_media_nft_events(social_media_id);
CREATE INDEX idx_social_media_nft_events_chain_id ON social_media_nft_events(chain_id);
CREATE INDEX idx_social_media_nft_events_block_number ON social_media_nft_events(block_number);

-- Create unique constraint to prevent duplicate events
CREATE UNIQUE INDEX idx_social_media_nft_events_unique 
ON social_media_nft_events(transaction_hash, token_id, chain_id);
