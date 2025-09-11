-- Consolidate listings table to include blockchain event tracking
-- This replaces the separate listing_events tables with a more efficient single table

-- Drop the redundant listing events tables
DROP TABLE IF EXISTS nft_listing_events;
DROP TABLE IF EXISTS nft_listing_sold_events;
DROP TABLE IF EXISTS nft_listing_cancelled_events;
DROP TABLE IF EXISTS non_nft_listing_events;
DROP TABLE IF EXISTS escrow_events;

-- Add blockchain tracking fields to existing listings table
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'nft_listings' AND column_name = 'chain_id') THEN
        ALTER TABLE nft_listings ADD COLUMN chain_id BIGINT DEFAULT 1;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'nft_listings' AND column_name = 'transaction_hash') THEN
        ALTER TABLE nft_listings ADD COLUMN transaction_hash VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'nft_listings' AND column_name = 'block_number') THEN
        ALTER TABLE nft_listings ADD COLUMN block_number BIGINT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'nft_listings' AND column_name = 'status') THEN
        ALTER TABLE nft_listings ADD COLUMN status VARCHAR(50) DEFAULT 'active';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'nft_listings' AND column_name = 'sold_at') THEN
        ALTER TABLE nft_listings ADD COLUMN sold_at TIMESTAMPTZ;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'nft_listings' AND column_name = 'buyer_address') THEN
        ALTER TABLE nft_listings ADD COLUMN buyer_address VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'nft_listings' AND column_name = 'sale_transaction_hash') THEN
        ALTER TABLE nft_listings ADD COLUMN sale_transaction_hash VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'nft_listings' AND column_name = 'sale_block_number') THEN
        ALTER TABLE nft_listings ADD COLUMN sale_block_number BIGINT;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'non_nft_listings' AND column_name = 'chain_id') THEN
        ALTER TABLE non_nft_listings ADD COLUMN chain_id BIGINT DEFAULT 1;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'non_nft_listings' AND column_name = 'transaction_hash') THEN
        ALTER TABLE non_nft_listings ADD COLUMN transaction_hash VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'non_nft_listings' AND column_name = 'block_number') THEN
        ALTER TABLE non_nft_listings ADD COLUMN block_number BIGINT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'non_nft_listings' AND column_name = 'status') THEN
        ALTER TABLE non_nft_listings ADD COLUMN status VARCHAR(50) DEFAULT 'active';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'non_nft_listings' AND column_name = 'sold_at') THEN
        ALTER TABLE non_nft_listings ADD COLUMN sold_at TIMESTAMPTZ;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'non_nft_listings' AND column_name = 'buyer_address') THEN
        ALTER TABLE non_nft_listings ADD COLUMN buyer_address VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'non_nft_listings' AND column_name = 'sale_transaction_hash') THEN
        ALTER TABLE non_nft_listings ADD COLUMN sale_transaction_hash VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'non_nft_listings' AND column_name = 'sale_block_number') THEN
        ALTER TABLE non_nft_listings ADD COLUMN sale_block_number BIGINT;
    END IF;
END $$;

DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'social_media_nft_listings' AND column_name = 'chain_id') THEN
        ALTER TABLE social_media_nft_listings ADD COLUMN chain_id BIGINT DEFAULT 1;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'social_media_nft_listings' AND column_name = 'transaction_hash') THEN
        ALTER TABLE social_media_nft_listings ADD COLUMN transaction_hash VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'social_media_nft_listings' AND column_name = 'block_number') THEN
        ALTER TABLE social_media_nft_listings ADD COLUMN block_number BIGINT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'social_media_nft_listings' AND column_name = 'status') THEN
        ALTER TABLE social_media_nft_listings ADD COLUMN status VARCHAR(50) DEFAULT 'active';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'social_media_nft_listings' AND column_name = 'sold_at') THEN
        ALTER TABLE social_media_nft_listings ADD COLUMN sold_at TIMESTAMPTZ;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'social_media_nft_listings' AND column_name = 'buyer_address') THEN
        ALTER TABLE social_media_nft_listings ADD COLUMN buyer_address VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'social_media_nft_listings' AND column_name = 'sale_transaction_hash') THEN
        ALTER TABLE social_media_nft_listings ADD COLUMN sale_transaction_hash VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'social_media_nft_listings' AND column_name = 'sale_block_number') THEN
        ALTER TABLE social_media_nft_listings ADD COLUMN sale_block_number BIGINT;
    END IF;
END $$;

-- Create indexes for blockchain tracking
CREATE INDEX IF NOT EXISTS idx_nft_listings_chain_id ON nft_listings(chain_id);
CREATE INDEX IF NOT EXISTS idx_nft_listings_status ON nft_listings(status);
CREATE INDEX IF NOT EXISTS idx_nft_listings_transaction_hash ON nft_listings(transaction_hash);
CREATE INDEX IF NOT EXISTS idx_nft_listings_block_number ON nft_listings(block_number);
CREATE INDEX IF NOT EXISTS idx_nft_listings_chain_status ON nft_listings(chain_id, status);

CREATE INDEX IF NOT EXISTS idx_non_nft_listings_chain_id ON non_nft_listings(chain_id);
CREATE INDEX IF NOT EXISTS idx_non_nft_listings_status ON non_nft_listings(status);
CREATE INDEX IF NOT EXISTS idx_non_nft_listings_transaction_hash ON non_nft_listings(transaction_hash);
CREATE INDEX IF NOT EXISTS idx_non_nft_listings_block_number ON non_nft_listings(block_number);
CREATE INDEX IF NOT EXISTS idx_non_nft_listings_chain_status ON non_nft_listings(chain_id, status);

CREATE INDEX IF NOT EXISTS idx_social_media_nft_listings_chain_id ON social_media_nft_listings(chain_id);
CREATE INDEX IF NOT EXISTS idx_social_media_nft_listings_status ON social_media_nft_listings(status);
CREATE INDEX IF NOT EXISTS idx_social_media_nft_listings_transaction_hash ON social_media_nft_listings(transaction_hash);
CREATE INDEX IF NOT EXISTS idx_social_media_nft_listings_block_number ON social_media_nft_listings(block_number);
CREATE INDEX IF NOT EXISTS idx_social_media_nft_listings_chain_status ON social_media_nft_listings(chain_id, status);

-- Add constraints for data integrity
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_name = 'nft_listings' AND constraint_name = 'check_nft_listing_status') THEN
        ALTER TABLE nft_listings ADD CONSTRAINT check_nft_listing_status CHECK (status IN ('active', 'sold', 'cancelled'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_name = 'non_nft_listings' AND constraint_name = 'check_non_nft_listing_status') THEN
        ALTER TABLE non_nft_listings ADD CONSTRAINT check_non_nft_listing_status CHECK (status IN ('active', 'sold', 'cancelled'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_name = 'social_media_nft_listings' AND constraint_name = 'check_social_media_listing_status') THEN
        ALTER TABLE social_media_nft_listings ADD CONSTRAINT check_social_media_listing_status CHECK (status IN ('active', 'sold', 'cancelled'));
    END IF;
END $$;
