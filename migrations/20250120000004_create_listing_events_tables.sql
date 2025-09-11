-- Create tables for listing-related blockchain events

-- NFT listing created events
CREATE TABLE nft_listing_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    listing_id BIGINT NOT NULL,
    nft_contract VARCHAR(255) NOT NULL,
    token_id BIGINT NOT NULL,
    seller_address VARCHAR(255) NOT NULL,
    price TEXT NOT NULL, -- Store as text to handle large numbers
    transaction_hash VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(transaction_hash, listing_id, chain_id)
);

-- NFT listing sold events
CREATE TABLE nft_listing_sold_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    listing_id BIGINT NOT NULL,
    buyer_address VARCHAR(255) NOT NULL,
    sale_price TEXT NOT NULL,
    transaction_hash VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(transaction_hash, listing_id, chain_id)
);

-- NFT listing cancelled events
CREATE TABLE nft_listing_cancelled_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    listing_id BIGINT NOT NULL,
    seller_address VARCHAR(255) NOT NULL,
    transaction_hash VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(transaction_hash, listing_id, chain_id)
);

-- Non-NFT listing events (websites, domains, etc.)
CREATE TABLE non_nft_listing_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    listing_id BIGINT NOT NULL,
    asset_type VARCHAR(100) NOT NULL,
    asset_id VARCHAR(255) NOT NULL,
    seller_address VARCHAR(255) NOT NULL,
    price TEXT NOT NULL,
    transaction_hash VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(transaction_hash, listing_id, chain_id)
);

-- Escrow events for manual transfers
CREATE TABLE escrow_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    listing_id BIGINT NOT NULL,
    buyer_address VARCHAR(255),
    seller_address VARCHAR(255),
    amount TEXT NOT NULL,
    event_type VARCHAR(50) NOT NULL, -- 'deposit', 'release', 'refund'
    transaction_hash VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(transaction_hash, listing_id, chain_id)
);

-- Create indexes for better query performance
CREATE INDEX idx_nft_listing_events_chain_id ON nft_listing_events(chain_id);
CREATE INDEX idx_nft_listing_events_listing_id ON nft_listing_events(listing_id);
CREATE INDEX idx_nft_listing_events_seller_address ON nft_listing_events(seller_address);
CREATE INDEX idx_nft_listing_events_block_number ON nft_listing_events(block_number);
CREATE INDEX idx_nft_listing_events_chain_listing ON nft_listing_events(chain_id, listing_id);

CREATE INDEX idx_nft_listing_sold_events_chain_id ON nft_listing_sold_events(chain_id);
CREATE INDEX idx_nft_listing_sold_events_listing_id ON nft_listing_sold_events(listing_id);
CREATE INDEX idx_nft_listing_sold_events_buyer_address ON nft_listing_sold_events(buyer_address);
CREATE INDEX idx_nft_listing_sold_events_block_number ON nft_listing_sold_events(block_number);
CREATE INDEX idx_nft_listing_sold_events_chain_listing ON nft_listing_sold_events(chain_id, listing_id);

CREATE INDEX idx_nft_listing_cancelled_events_chain_id ON nft_listing_cancelled_events(chain_id);
CREATE INDEX idx_nft_listing_cancelled_events_listing_id ON nft_listing_cancelled_events(listing_id);
CREATE INDEX idx_nft_listing_cancelled_events_seller_address ON nft_listing_cancelled_events(seller_address);
CREATE INDEX idx_nft_listing_cancelled_events_block_number ON nft_listing_cancelled_events(block_number);
CREATE INDEX idx_nft_listing_cancelled_events_chain_listing ON nft_listing_cancelled_events(chain_id, listing_id);

CREATE INDEX idx_non_nft_listing_events_chain_id ON non_nft_listing_events(chain_id);
CREATE INDEX idx_non_nft_listing_events_listing_id ON non_nft_listing_events(listing_id);
CREATE INDEX idx_non_nft_listing_events_asset_type ON non_nft_listing_events(asset_type);
CREATE INDEX idx_non_nft_listing_events_seller_address ON non_nft_listing_events(seller_address);
CREATE INDEX idx_non_nft_listing_events_block_number ON non_nft_listing_events(block_number);
CREATE INDEX idx_non_nft_listing_events_chain_listing ON non_nft_listing_events(chain_id, listing_id);

CREATE INDEX idx_escrow_events_chain_id ON escrow_events(chain_id);
CREATE INDEX idx_escrow_events_listing_id ON escrow_events(listing_id);
CREATE INDEX idx_escrow_events_event_type ON escrow_events(event_type);
CREATE INDEX idx_escrow_events_buyer_address ON escrow_events(buyer_address);
CREATE INDEX idx_escrow_events_seller_address ON escrow_events(seller_address);
CREATE INDEX idx_escrow_events_block_number ON escrow_events(block_number);
CREATE INDEX idx_escrow_events_chain_listing ON escrow_events(chain_id, listing_id);
