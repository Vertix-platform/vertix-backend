use crate::config::Config;
use crate::models::{ValueResponse, VerifyResponse};

pub async fn verify_asset(
    asset_type: &str,
    asset_id: &str,
    proof: &str,
    _config: &Config,
) -> VerifyResponse {
    // Fake logic: Pretend we checked the asset
    match asset_type {
        "social_media" => {
            // Later: Call X API to verify proof (e.g., OAuth token)
            VerifyResponse {
                is_verified: !asset_id.is_empty() && !proof.is_empty(),
            }
        }
        "domain" => {
            // Later: Check DNS TXT record
            VerifyResponse {
                is_verified: asset_id == "example.com" && !proof.is_empty(),
            }
        }
        "app" | "website" => VerifyResponse {
            is_verified: !asset_id.is_empty() && !proof.is_empty(),
        },
        _ => VerifyResponse {
            is_verified: false,
        },
    }
}

pub async fn calculate_value(asset_type: &str, asset_id: &str, config: &Config) -> ValueResponse {
    match asset_type {
        "social_media" => {
            // Fake data: Pretend we got this from X API
            let followers = 10_000; // 10,000 followers
            let tweets = 1_000;     // 1,000 tweets
            // Value = (followers * $0.05) + (tweets * $0.01)
            let value_usd = (followers as f64 * config.valuation_weight_followers)
                + (tweets as f64 * config.valuation_weight_tweets);
            ValueResponse {
                value: (value_usd * 1_000_000.0) as u64, // $510 * 1,000,000
            }
        }
        "domain" => {
            // Fake value for domains
            ValueResponse {
                value: if asset_id == "example.com" {
                    50_000_000
                } else {
                    0
                }, // $50
            }
        }
        "app" | "website" => ValueResponse {
            value: 10_000_000, // $10
        },
        _ => ValueResponse { value: 0 },
    }
}