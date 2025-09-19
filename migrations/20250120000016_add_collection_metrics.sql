-- Add total_volume and floor_price columns to collections table
ALTER TABLE collections 
ADD COLUMN total_volume_wei NUMERIC(78, 0) DEFAULT 0,
ADD COLUMN floor_price_wei NUMERIC(78, 0) DEFAULT NULL;

-- Create index for volume queries
CREATE INDEX idx_collections_total_volume ON collections(total_volume_wei);

-- Create index for floor price queries
CREATE INDEX idx_collections_floor_price ON collections(floor_price_wei);

-- Create function to calculate collection metrics
CREATE OR REPLACE FUNCTION calculate_collection_metrics(collection_id_param BIGINT, chain_id_param BIGINT)
RETURNS TABLE(total_volume_wei NUMERIC(78, 0), floor_price_wei NUMERIC(78, 0)) AS $$
DECLARE
    total_vol NUMERIC(78, 0) := 0;
    floor_price NUMERIC(78, 0) := NULL;
BEGIN
    -- Calculate total volume from sales
    SELECT COALESCE(SUM(s.price_wei), 0)
    INTO total_vol
    FROM nft_sale_events s
    JOIN nft_mint_events m ON s.token_id = m.token_id AND s.chain_id = m.chain_id
    WHERE m.collection_id = collection_id_param
    AND s.chain_id = chain_id_param;
    
    -- Calculate floor price from active listings
    SELECT MIN(l.price_wei)
    INTO floor_price
    FROM nft_listing_events l
    JOIN nft_mint_events m ON l.token_id = m.token_id AND l.chain_id = m.chain_id
    WHERE m.collection_id = collection_id_param
    AND l.chain_id = chain_id_param
    AND l.event_type = 'LISTED'
    AND l.created_at = (
        SELECT MAX(l2.created_at)
        FROM nft_listing_events l2
        WHERE l2.chain_id = l.chain_id
        AND l2.nft_contract = l.nft_contract
        AND l2.token_id = l.token_id
        AND l2.event_type IN ('LISTED', 'AUCTION_STARTED', 'DELISTED', 'SOLD')
    )
    AND NOT EXISTS (
        SELECT 1 FROM nft_listing_events l3
        WHERE l3.chain_id = l.chain_id
        AND l3.nft_contract = l.nft_contract
        AND l3.token_id = l.token_id
        AND l3.event_type IN ('DELISTED', 'SOLD')
        AND l3.created_at > l.created_at
    );
    
    total_volume_wei := total_vol;
    floor_price_wei := floor_price;
    
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Create function to update collection metrics
CREATE OR REPLACE FUNCTION update_collection_metrics()
RETURNS TRIGGER AS $$
DECLARE
    collection_id_val BIGINT;
    chain_id_val BIGINT;
    total_vol NUMERIC(78, 0);
    floor_price NUMERIC(78, 0);
BEGIN
    -- Get collection_id from the mint event
    SELECT m.collection_id, COALESCE(NEW.chain_id, OLD.chain_id)
    INTO collection_id_val, chain_id_val
    FROM nft_mint_events m
    WHERE m.token_id = COALESCE(NEW.token_id, OLD.token_id)
    AND m.chain_id = COALESCE(NEW.chain_id, OLD.chain_id)
    LIMIT 1;
    
    -- Only proceed if we found a collection
    IF collection_id_val IS NOT NULL THEN
        -- Calculate total volume from sales
        SELECT COALESCE(SUM(s.price_wei), 0)
        INTO total_vol
        FROM nft_sale_events s
        JOIN nft_mint_events m ON s.token_id = m.token_id AND s.chain_id = m.chain_id
        WHERE m.collection_id = collection_id_val
        AND s.chain_id = chain_id_val;
        
        -- Calculate floor price from active listings
        SELECT MIN(l.price_wei)
        INTO floor_price
        FROM nft_listing_events l
        JOIN nft_mint_events m ON l.token_id = m.token_id AND l.chain_id = m.chain_id
        WHERE m.collection_id = collection_id_val
        AND l.chain_id = chain_id_val
        AND l.event_type = 'LISTED'
        AND l.created_at = (
            SELECT MAX(l2.created_at)
            FROM nft_listing_events l2
            WHERE l2.chain_id = l.chain_id
            AND l2.nft_contract = l.nft_contract
            AND l2.token_id = l.token_id
            AND l2.event_type IN ('LISTED', 'AUCTION_STARTED', 'DELISTED', 'SOLD')
        )
        AND NOT EXISTS (
            SELECT 1 FROM nft_listing_events l3
            WHERE l3.chain_id = l.chain_id
            AND l3.nft_contract = l.nft_contract
            AND l3.token_id = l.token_id
            AND l3.event_type IN ('DELISTED', 'SOLD')
            AND l3.created_at > l.created_at
        );
        
        -- Update the collection
        UPDATE collections 
        SET 
            total_volume_wei = total_vol,
            floor_price_wei = floor_price,
            updated_at = NOW()
        WHERE collection_id = collection_id_val 
        AND chain_id = chain_id_val;
    END IF;
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Create triggers to automatically update collection metrics
CREATE TRIGGER update_collection_metrics_on_sale
    AFTER INSERT OR UPDATE OR DELETE ON nft_sale_events
    FOR EACH ROW
    EXECUTE FUNCTION update_collection_metrics();

CREATE TRIGGER update_collection_metrics_on_listing
    AFTER INSERT OR UPDATE OR DELETE ON nft_listing_events
    FOR EACH ROW
    EXECUTE FUNCTION update_collection_metrics();
