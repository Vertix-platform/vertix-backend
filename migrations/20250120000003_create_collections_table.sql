-- Create collections table for NFT collections created on blockchain
CREATE TABLE collections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id BIGINT NOT NULL,
    chain_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    symbol VARCHAR(50) NOT NULL,
    image TEXT,
    max_supply BIGINT NOT NULL DEFAULT 0,
    current_supply BIGINT NOT NULL DEFAULT 0,
    creator_address VARCHAR(42) NOT NULL,
    transaction_hash VARCHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE UNIQUE INDEX idx_collections_collection_id_chain_id ON collections(collection_id, chain_id);
CREATE INDEX idx_collections_chain_id ON collections(chain_id);
CREATE INDEX idx_collections_creator_address ON collections(creator_address);
CREATE INDEX idx_collections_name ON collections(name);
CREATE INDEX idx_collections_symbol ON collections(symbol);
CREATE INDEX idx_collections_block_number ON collections(block_number);

-- Create trigger for updated_at
CREATE TRIGGER update_collections_updated_at 
    BEFORE UPDATE ON collections 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();
