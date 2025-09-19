-- Create blockchain events table for general event storage
CREATE TABLE blockchain_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id BIGINT NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    event_signature VARCHAR(66) NOT NULL,
    event_data JSONB,
    transaction_hash VARCHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    log_index INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_blockchain_events_chain_id ON blockchain_events(chain_id);
CREATE INDEX idx_blockchain_events_contract_address ON blockchain_events(contract_address);
CREATE INDEX idx_blockchain_events_event_signature ON blockchain_events(event_signature);
CREATE INDEX idx_blockchain_events_transaction_hash ON blockchain_events(transaction_hash);
CREATE INDEX idx_blockchain_events_block_number ON blockchain_events(block_number);
CREATE INDEX idx_blockchain_events_created_at ON blockchain_events(created_at);

-- Create unique constraint to prevent duplicate events
CREATE UNIQUE INDEX idx_blockchain_events_unique 
ON blockchain_events(transaction_hash, log_index, chain_id);
