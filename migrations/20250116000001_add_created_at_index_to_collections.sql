-- Add index on created_at column for faster ORDER BY queries
CREATE INDEX idx_collections_created_at ON collections(created_at DESC);

-- Add composite index for better performance on common queries
CREATE INDEX idx_collections_created_at_chain_id ON collections(created_at DESC, chain_id);
