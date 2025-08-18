-- Create listings table for NFT and non-NFT asset listings

-- NFT listings table
CREATE TABLE nft_listings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    listing_id BIGINT NOT NULL UNIQUE,
    creator_address VARCHAR(42) NOT NULL,
    nft_contract VARCHAR(42) NOT NULL,
    token_id BIGINT NOT NULL,
    price BIGINT NOT NULL,
    description TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    is_auction BOOLEAN NOT NULL DEFAULT false,
    metadata_uri TEXT,
    transaction_hash VARCHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Non-NFT asset listings table
CREATE TABLE non_nft_listings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    listing_id BIGINT NOT NULL UNIQUE,
    creator_address VARCHAR(42) NOT NULL,
    asset_type SMALLINT NOT NULL, -- 1=SocialMedia, 2=Website, 3=Domain, 4=Application, 5=GamingAccount
    asset_id TEXT NOT NULL,
    price BIGINT NOT NULL,
    description TEXT NOT NULL,
    platform VARCHAR(50), -- x, instagram, facebook, youtube, etc.
    identifier TEXT, -- username, channel_id, domain, etc.
    metadata_uri TEXT,
    verification_proof TEXT,
    transaction_hash VARCHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Social media NFT listings table
CREATE TABLE social_media_nft_listings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    listing_id BIGINT NOT NULL UNIQUE,
    creator_address VARCHAR(42) NOT NULL,
    token_id BIGINT NOT NULL,
    price BIGINT NOT NULL,
    description TEXT NOT NULL,
    social_media_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    is_auction BOOLEAN NOT NULL DEFAULT false,
    transaction_hash VARCHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better query performance
CREATE INDEX idx_nft_listings_listing_id ON nft_listings(listing_id);
CREATE INDEX idx_nft_listings_creator_address ON nft_listings(creator_address);
CREATE INDEX idx_nft_listings_nft_contract ON nft_listings(nft_contract);
CREATE INDEX idx_nft_listings_token_id ON nft_listings(token_id);
CREATE INDEX idx_nft_listings_active ON nft_listings(active);
CREATE INDEX idx_nft_listings_price ON nft_listings(price);
CREATE INDEX idx_nft_listings_created_at ON nft_listings(created_at);

CREATE INDEX idx_non_nft_listings_listing_id ON non_nft_listings(listing_id);
CREATE INDEX idx_non_nft_listings_creator_address ON non_nft_listings(creator_address);
CREATE INDEX idx_non_nft_listings_asset_type ON non_nft_listings(asset_type);
CREATE INDEX idx_non_nft_listings_platform ON non_nft_listings(platform);
CREATE INDEX idx_non_nft_listings_price ON non_nft_listings(price);
CREATE INDEX idx_non_nft_listings_created_at ON non_nft_listings(created_at);

CREATE INDEX idx_social_media_nft_listings_listing_id ON social_media_nft_listings(listing_id);
CREATE INDEX idx_social_media_nft_listings_creator_address ON social_media_nft_listings(creator_address);
CREATE INDEX idx_social_media_nft_listings_token_id ON social_media_nft_listings(token_id);
CREATE INDEX idx_social_media_nft_listings_active ON social_media_nft_listings(active);
CREATE INDEX idx_social_media_nft_listings_price ON social_media_nft_listings(price);
CREATE INDEX idx_social_media_nft_listings_created_at ON social_media_nft_listings(created_at);

-- Create full-text search indexes for descriptions
CREATE INDEX idx_nft_listings_description_fts ON nft_listings USING gin(to_tsvector('english', description));
CREATE INDEX idx_non_nft_listings_description_fts ON non_nft_listings USING gin(to_tsvector('english', description));
CREATE INDEX idx_social_media_nft_listings_description_fts ON social_media_nft_listings USING gin(to_tsvector('english', description));

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_nft_listings_updated_at BEFORE UPDATE ON nft_listings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_non_nft_listings_updated_at BEFORE UPDATE ON non_nft_listings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_social_media_nft_listings_updated_at BEFORE UPDATE ON social_media_nft_listings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
