# backend

```
vertix-backend/
├── src/
│   ├── db.rs           # Database connection and queries
│   ├── auth.rs         # Authentication logic
│   ├── models.rs       # Structs for User, SocialMediaLink
│   ├── routes.rs       # API routes
│   ├── main.rs         # Entry point
├── .env                # Environment variables
├── schema.sql          # Database schema
├── Cargo.toml          # Dependencies
```


## Project diagram

```
Frontend (React)       Backend (Rust)         Blockchain (Ethereum)      Database (PostgreSQL)
  |                      |                        |                         |
  |--- Login (email) ---->| /login                |                         |
  |<-- JWT --------------| Generate JWT           |                         | Update users
  |                      |                        |                         |
  |--- Connect Wallet -->| /connect-wallet        |                         |
  | Sign Message         | Verify Signature       |                         | Store wallet_address
  |                      |                        |                         |
  |--- Link X ---------->| /auth/link/x (JWT)     |                         |
  | OAuth Flow          | Store social media     |                         | Update social_media_links
  |                      |                        |                         |
  |--- Mint NFT -------->|                        | Call mintSocialMediaNFT |
  | Sign Transaction    | /verify (check wallet) | Verify via AssetVerifier|
```