use std::env;

pub struct Config {
    pub x_api_key: String,
    pub instagram_access_token: String,
    pub twitch_client_id: String,
    pub facebook_access_token: String,
    pub valuation_weight_followers: f64, // $ per follower
    pub valuation_weight_tweets: f64,    // $ per tweet
}

impl Config {
    pub fn load() -> Self {
        Config {
            x_api_key: env::var("X_API_KEY").expect("X_API_KEY not set"),
            instagram_access_token: env::var("INSTAGRAM_ACCESS_TOKEN")
                .expect("INSTAGRAM_ACCESS_TOKEN not set"),
            twitch_client_id: env::var("TWITCH_CLIENT_ID").expect("TWITCH_CLIENT_ID not set"),
            facebook_access_token: env::var("FACEBOOK_ACCESS_TOKEN")
                .expect("FACEBOOK_ACCESS_TOKEN not set"),
            valuation_weight_followers: env::var("VALUATION_WEIGHT_FOLLOWERS")
                .unwrap_or("0.05")
                .parse()
                .expect("Invalid VALUATION_WEIGHT_FOLLOWERS"),
            valuation_weight_tweets: env::var("VALUATION_WEIGHT_TWEETS")
                .unwrap_or("0.01")
                .parse()
                .expect("Invalid VALUATION_WEIGHT_TWEETS"),
        }
    }
}