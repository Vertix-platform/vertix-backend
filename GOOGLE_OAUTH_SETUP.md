# Google OAuth Setup Guide

To enable Google OAuth authentication in Vertix, you need to set up Google OAuth credentials and configure the environment variables.

## Step 1: Create Google OAuth Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API and Google OAuth2 API
4. Go to "Credentials" in the left sidebar
5. Click "Create Credentials" → "OAuth 2.0 Client IDs"
6. Choose "Web application" as the application type
7. Add the following authorized redirect URIs:
   - `http://localhost:3000/auth/google-callback` (for development)
   - `https://yourdomain.com/auth/google-callback` (for production)
8. Copy the Client ID and Client Secret

## Step 2: Set Environment Variables

Create a `.env` file in the `vertix-backend` directory with the following variables:

```env
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/vertix_db

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here
JWT_EXPIRY=3600

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id-here
GOOGLE_CLIENT_SECRET=your-google-client-secret-here
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google-callback

# Server Configuration
PORT=8080
RUST_LOG=info
```

## Step 3: Test the Setup

1. Start the backend server: `cargo run`
2. Start the frontend: `npm run dev`
3. Navigate to the login page
4. Click "Google" to test the OAuth flow

## Troubleshooting

- **"GOOGLE_CLIENT_ID must be set"**: Make sure you've set the environment variables correctly
- **"Invalid redirect URI"**: Check that the redirect URI in Google Console matches your environment variable
- **"OAuth consent screen not configured"**: Make sure you've configured the OAuth consent screen in Google Console

## Security Notes

- Never commit your `.env` file to version control
- Use different OAuth credentials for development and production
- Regularly rotate your OAuth secrets
- Use HTTPS in production for secure OAuth flows
