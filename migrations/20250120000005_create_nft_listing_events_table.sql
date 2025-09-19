-- Create NFT listing events table for blockchain events
CREATE TABLE nft_listing_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    listing_id BIGINT NOT NULL,
    nft_contract VARCHAR(42) NOT NULL,
    token_id BIGINT NOT NULL,
    seller_address VARCHAR(42) NOT NULL,
    price_wei NUMERIC(78, 0) NOT NULL,
    is_auction BOOLEAN NOT NULL DEFAULT FALSE,
    auction_end_time TIMESTAMP WITH TIME ZONE,
    reserve_price_wei NUMERIC(78, 0),
    transaction_hash VARCHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    event_type VARCHAR(20) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_nft_listing_events_chain_id ON nft_listing_events(chain_id);
CREATE INDEX idx_nft_listing_events_listing_id ON nft_listing_events(listing_id);
CREATE INDEX idx_nft_listing_events_nft_contract ON nft_listing_events(nft_contract);
CREATE INDEX idx_nft_listing_events_token_id ON nft_listing_events(token_id);
CREATE INDEX idx_nft_listing_events_seller ON nft_listing_events(seller_address);
CREATE INDEX idx_nft_listing_events_event_type ON nft_listing_events(event_type);
CREATE INDEX idx_nft_listing_events_created_at ON nft_listing_events(created_at);

-- Create unique constraint to prevent duplicate events
CREATE UNIQUE INDEX idx_nft_listing_events_unique 
ON nft_listing_events(transaction_hash, listing_id, chain_id);

-- Create composite index for active listings query
CREATE INDEX idx_nft_listing_events_active_listings 
ON nft_listing_events(chain_id, nft_contract, token_id, event_type) 
WHERE event_type IN ('LISTED', 'AUCTION_STARTED');

-- Create trigger for updated_at
CREATE TRIGGER update_nft_listing_events_updated_at
    BEFORE UPDATE ON nft_listing_events
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
