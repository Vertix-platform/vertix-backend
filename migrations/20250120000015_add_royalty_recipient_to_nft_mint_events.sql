-- Add royalty_recipient field to nft_mint_events table
ALTER TABLE nft_mint_events 
ADD COLUMN royalty_recipient VARCHAR(42);

-- Create index for royalty_recipient
CREATE INDEX idx_nft_mint_events_royalty_recipient ON nft_mint_events(royalty_recipient);
