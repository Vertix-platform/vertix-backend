-- Create tables for blockchain events tracking

-- NFT mint events table
CREATE TABLE nft_mint_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    to_address VARCHAR(255) NOT NULL,
    token_id BIGINT NOT NULL,
    collection_id BIGINT,
    transaction_hash VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(transaction_hash, token_id, chain_id)
);

-- Collection events table
CREATE TABLE collection_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    collection_id BIGINT NOT NULL,
    creator_address VARCHAR(255) NOT NULL,
    transaction_hash VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(transaction_hash, collection_id, chain_id)
);

-- Social media NFT events table
CREATE TABLE social_media_nft_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    to_address VARCHAR(255) NOT NULL,
    token_id BIGINT NOT NULL,
    social_media_id VARCHAR(255) NOT NULL,
    transaction_hash VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(transaction_hash, token_id, chain_id)
);

-- Create indexes for better query performance
CREATE INDEX idx_nft_mint_events_chain_id ON nft_mint_events(chain_id);
CREATE INDEX idx_nft_mint_events_to_address ON nft_mint_events(to_address);
CREATE INDEX idx_nft_mint_events_token_id ON nft_mint_events(token_id);
CREATE INDEX idx_nft_mint_events_collection_id ON nft_mint_events(collection_id);
CREATE INDEX idx_nft_mint_events_block_number ON nft_mint_events(block_number);
CREATE INDEX idx_nft_mint_events_chain_token ON nft_mint_events(chain_id, token_id);

CREATE INDEX idx_collection_events_chain_id ON collection_events(chain_id);
CREATE INDEX idx_collection_events_collection_id ON collection_events(collection_id);
CREATE INDEX idx_collection_events_creator_address ON collection_events(creator_address);
CREATE INDEX idx_collection_events_block_number ON collection_events(block_number);
CREATE INDEX idx_collection_events_chain_collection ON collection_events(chain_id, collection_id);

CREATE INDEX idx_social_media_nft_events_chain_id ON social_media_nft_events(chain_id);
CREATE INDEX idx_social_media_nft_events_to_address ON social_media_nft_events(to_address);
CREATE INDEX idx_social_media_nft_events_token_id ON social_media_nft_events(token_id);
CREATE INDEX idx_social_media_nft_events_social_media_id ON social_media_nft_events(social_media_id);
CREATE INDEX idx_social_media_nft_events_block_number ON social_media_nft_events(block_number);
CREATE INDEX idx_social_media_nft_events_chain_token ON social_media_nft_events(chain_id, token_id);
