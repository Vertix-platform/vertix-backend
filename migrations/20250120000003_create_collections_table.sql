-- Create collections table to store collection details
CREATE TABLE collections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id BIGINT NOT NULL,
    chain_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    symbol VARCHAR(50) NOT NULL,
    image TEXT,
    max_supply BIGINT NOT NULL DEFAULT 0,
    current_supply BIGINT NOT NULL DEFAULT 0,
    creator_address VARCHAR(255) NOT NULL,
    transaction_hash VARCHAR(255) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(collection_id, chain_id)
);

-- Create indexes for better query performance
CREATE INDEX idx_collections_collection_id ON collections(collection_id);
CREATE INDEX idx_collections_chain_id ON collections(chain_id);
CREATE INDEX idx_collections_creator_address ON collections(creator_address);
CREATE INDEX idx_collections_block_number ON collections(block_number);
CREATE INDEX idx_collections_name ON collections(name);
CREATE INDEX idx_collections_symbol ON collections(symbol);
CREATE INDEX idx_collections_chain_collection ON collections(chain_id, collection_id);

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_collections_updated_at 
    BEFORE UPDATE ON collections 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();
