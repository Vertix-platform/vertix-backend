-- Create chain starting blocks table to track the first block for each chain
CREATE TABLE chain_starting_blocks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL UNIQUE,
    chain_name VARCHAR(100) NOT NULL,
    starting_block_number BIGINT NOT NULL,
    contract_addresses JSONB NOT NULL, -- Store all contract addresses for this chain
    deployment_tx_hash VARCHAR(66), -- First deployment transaction hash
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_chain_starting_blocks_chain_id ON chain_starting_blocks(chain_id);
CREATE INDEX idx_chain_starting_blocks_starting_block ON chain_starting_blocks(starting_block_number);

-- Create trigger for updated_at
CREATE TRIGGER update_chain_starting_blocks_updated_at 
    BEFORE UPDATE ON chain_starting_blocks 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();
