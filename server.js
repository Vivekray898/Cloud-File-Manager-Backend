// server.js - Node.js Backend for Cloud File Manager

// --- Required Modules ---
const express = require('express');
const axios = require('axios'); // For making HTTP requests to Microsoft Graph API
const session = require('express-session'); // For managing user sessions and storing tokens
const cors = require('cors'); // To allow requests from your frontend domain
// const path = require('path'); // Not strictly needed for this setup, can be removed if desired

// --- Configuration ---
// IMPORTANT: These are now read from environment variables for security!
// Make sure to set these in your Render dashboard under Environment Variables.
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI; // This will be your Render app's callback URL
const FRONTEND_URL = process.env.FRONTEND_URL; // This will be your InfinityFree domain

// Microsoft Graph API Endpoints
const MSGRAPH_AUTH_AUTHORIZE_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
const MSGRAPH_AUTH_TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
const MSGRAPH_API_BASE_URL = 'https://graph.microsoft.com/v1.0';

// Scopes required for OneDrive file access
const SCOPES = 'openid profile User.Read Files.ReadWrite.All offline_access';

// --- Express App Setup ---
const app = express();
const PORT = process.env.PORT || 3000; // Render will set process.env.PORT for you

// Middleware
app.use(express.json()); // For parsing JSON request bodies
app.use(express.urlencoded({ extended: true })); // For parsing URL-encoded request bodies

// Configure CORS to allow requests from your frontend
app.use(cors({
    origin: FRONTEND_URL, // Allow requests only from your frontend domain
    credentials: true // Allow cookies/session headers (important for sessions)
}));

// Session middleware setup
// In a production environment, you should use a more robust session store
// like 'connect-mongo' or 'connect-redis' instead of the default MemoryStore,
// especially if you expect high traffic or need session persistence across restarts.
app.use(session({
    secret: process.env.SESSION_SECRET_KEY, // Read from environment variable
    resave: false, // Don't save session if unmodified
    saveUninitialized: true, // Save new sessions
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
        sameSite: 'Lax', // Protects against CSRF attacks
        maxAge: 24 * 60 * 60 * 1000 // Session max age (e.g., 24 hours)
    }
}));

// --- Helper Function to Refresh Token ---
// This middleware attempts to refresh the access token if it's expired
// or missing, using the stored refresh token.
async function refreshToken(req, res, next) {
    // If no refresh token is available, or if the access token is still valid,
    // proceed to the next middleware/route handler.
    if (!req.session.refreshToken || (req.session.accessToken && req.session.expiresAt > Date.now())) {
        return next();
    }

    console.log('Access token expired or missing, attempting to refresh...');
    try {
        const tokenResponse = await axios.post(MSGRAPH_AUTH_TOKEN_URL, new URLSearchParams({
            client_id: CLIENT_ID,
            scope: SCOPES,
            refresh_token: req.session.refreshToken,
            grant_type: 'refresh_token',
            client_secret: CLIENT_SECRET,
            redirect_uri: REDIRECT_URI // Required even for refresh token flow
        }).toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const { access_token, refresh_token, expires_in } = tokenResponse.data;

        // Update session with new tokens.
        // A new refresh token might be returned, or the old one might remain valid.
        req.session.accessToken = access_token;
        req.session.refreshToken = refresh_token || req.session.refreshToken;
        req.session.expiresAt = Date.now() + (expires_in * 1000); // Convert seconds to milliseconds for expiry

        console.log('Token refreshed successfully!');
        next(); // Proceed to the original route handler
    } catch (error) {
        console.error('Error refreshing token:', error.response ? error.response.data : error.message);
        // If token refresh fails, destroy the session and redirect to re-authenticate.
        req.session.destroy(() => {
            res.redirect(`${FRONTEND_URL}?authSuccess=false&message=${encodeURIComponent('Session expired. Please re-authenticate.')}`);
        });
    }
}

// Apply the refresh token middleware to all routes that require authentication
app.use(['/upload-url', '/download-url', '/list-files'], refreshToken);


// --- Routes ---

// 1. Microsoft OAuth Initiation Endpoint
// This route redirects the user to Microsoft's authorization endpoint.
app.get('/auth/microsoft', (req, res) => {
    const authUrl = `${MSGRAPH_AUTH_AUTHORIZE_URL}?` + new URLSearchParams({
        client_id: CLIENT_ID,
        response_type: 'code', // We are requesting an authorization code
        redirect_uri: REDIRECT_URI,
        response_mode: 'query', // Microsoft will send the code back as a query parameter
        scope: SCOPES,
        state: 'random_state_string' // Recommended for CSRF protection. In a real app, generate a unique one per request.
    }).toString();
    res.redirect(authUrl);
});

// 2. Microsoft OAuth Callback Endpoint
// Microsoft redirects the user back to this endpoint after authorization.
app.get('/auth/microsoft/callback', async (req, res) => {
    const { code, state, error, error_description } = req.query;

    // Handle errors returned by Microsoft (e.g., user denied permissions)
    if (error) {
        console.error('OAuth callback error:', error_description);
        return res.redirect(`${FRONTEND_URL}?authSuccess=false&message=${encodeURIComponent(error_description || 'Authentication failed.')}`);
    }

    // Basic state validation to prevent CSRF attacks.
    // Ensure the 'state' parameter matches what was sent in the initial request.
    if (state !== 'random_state_string') {
        console.warn('State mismatch in OAuth callback.');
        return res.redirect(`${FRONTEND_URL}?authSuccess=false&message=${encodeURIComponent('Authentication failed: State mismatch.')}`);
    }

    try {
        // Exchange the authorization code for an access token and refresh token.
        const tokenResponse = await axios.post(MSGRAPH_AUTH_TOKEN_URL, new URLSearchParams({
            client_id: CLIENT_ID,
            scope: SCOPES,
            code: code,
            redirect_uri: REDIRECT_URI,
            grant_type: 'authorization_code', // Indicates we are exchanging a code
            client_secret: CLIENT_SECRET
        }).toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const { access_token, refresh_token, expires_in } = tokenResponse.data;

        // Store the tokens and their expiry time in the user's session.
        req.session.accessToken = access_token;
        req.session.refreshToken = refresh_token;
        req.session.expiresAt = Date.now() + (expires_in * 1000); // Convert seconds to milliseconds

        console.log('Authentication successful. Tokens stored in session.');
        // Redirect back to the frontend with success message.
        res.redirect(`${FRONTEND_URL}?authSuccess=true&message=${encodeURIComponent('Authenticated successfully!')}`);

    } catch (error) {
        console.error('Error exchanging code for token:', error.response ? error.response.data : error.message);
        // Redirect back to the frontend with an error message if token exchange fails.
        res.redirect(`${FRONTEND_URL}?authSuccess=false&message=${encodeURIComponent('Failed to get access token.')}`);
    }
});

// 3. Endpoint to Get a Pre-signed Upload URL
// The frontend calls this to get a URL to directly upload a file to OneDrive.
app.get('/upload-url', async (req, res) => {
    // Check if the user is authenticated (has an access token in session).
    if (!req.session.accessToken) {
        return res.status(401).json({ message: 'Not authenticated. Please authenticate first.' });
    }

    const filename = req.query.filename;
    if (!filename) {
        return res.status(400).json({ message: 'Filename is required for upload.' });
    }

    try {
        // Microsoft Graph API provides an 'upload session' for robust file uploads,
        // especially for larger files. This creates the session and returns a URL.
        const createUploadSessionResponse = await axios.post(
            `${MSGRAPH_API_BASE_URL}/me/drive/root:/${encodeURIComponent(filename)}:/createUploadSession`,
            {}, // Empty body for createUploadSession request
            {
                headers: {
                    'Authorization': `Bearer ${req.session.accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const uploadUrl = createUploadSessionResponse.data.uploadUrl;
        res.json({ uploadUrl }); // Send the pre-signed upload URL back to the frontend

    } catch (error) {
        console.error('Error getting upload URL:', error.response ? error.response.data : error.message);
        res.status(500).json({ message: 'Failed to get upload URL.', error: error.response ? error.response.data : error.message });
    }
});

// 4. Endpoint to Get a Pre-signed Download URL
// The frontend calls this to get a URL to directly download a file from OneDrive.
app.get('/download-url', async (req, res) => {
    // Check if the user is authenticated.
    if (!req.session.accessToken) {
        return res.status(401).json({ message: 'Not authenticated. Please authenticate first.' });
    }

    const filename = req.query.filename;
    if (!filename) {
        return res.status(400).json({ message: 'Filename is required for download.' });
    }

    try {
        // Get file metadata from Microsoft Graph API to find its download URL.
        const fileMetadataResponse = await axios.get(
            `${MSGRAPH_API_BASE_URL}/me/drive/root:/${encodeURIComponent(filename)}`,
            {
                headers: {
                    'Authorization': `Bearer ${req.session.accessToken}`
                }
            }
        );

        // The '@microsoft.graph.downloadUrl' property contains the pre-signed URL.
        const downloadUrl = fileMetadataResponse.data['@microsoft.graph.downloadUrl'];
        if (!downloadUrl) {
            return res.status(404).json({ message: 'Download URL not found for this file.' });
        }

        res.json({ downloadUrl }); // Send the pre-signed download URL back to the frontend

    } catch (error) {
        console.error('Error getting download URL:', error.response ? error.response.data : error.message);
        // Handle specific 404 (Not Found) error for the file.
        if (error.response && error.response.status === 404) {
            res.status(404).json({ message: `File "${filename}" not found.` });
        } else {
            res.status(500).json({ message: 'Failed to get download URL.', error: error.response ? error.response.data : error.message });
        }
    }
});

// 5. Endpoint to List Files in User's OneDrive
// The frontend calls this to display a list of files.
app.get('/list-files', async (req, res) => {
    // Check if the user is authenticated.
    if (!req.session.accessToken) {
        return res.status(401).json({ message: 'Not authenticated. Please authenticate first.' });
    }

    try {
        // Fetch children (files and folders) from the root of the user's drive.
        const driveItemsResponse = await axios.get(
            `${MSGRAPH_API_BASE_URL}/me/drive/root/children`,
            {
                headers: {
                    'Authorization': `Bearer ${req.session.accessToken}`
                },
                params: {
                    // Select only necessary fields to reduce the response payload size.
                    '$select': 'id,name,size,file,folder'
                }
            }
        );

        // Filter the results to include only files (not folders) and map them
        // to a simpler structure for the frontend.
        const files = driveItemsResponse.data.value
            .filter(item => item.file) // Keep only items that are files
            .map(item => ({
                id: item.id,
                name: item.name,
                size: item.size // File size in bytes
            }));

        res.json({ files }); // Send the list of files back to the frontend

    } catch (error) {
        console.error('Error listing files:', error.response ? error.response.data : error.message);
        res.status(500).json({ message: 'Failed to list files.', error: error.response ? error.response.data : error.message });
    }
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Backend server running on port ${PORT}`);
    console.log(`Please ensure you've updated all environment variables in Render.`);
    console.log(`CLIENT_ID: ${CLIENT_ID}`);
    console.log(`REDIRECT_URI: ${REDIRECT_URI}`);
    console.log(`FRONTEND_URL: ${FRONTEND_URL}`);
});
