// functions/github-auth.js

// This Cloudflare Pages Function acts as a GitHub OAuth proxy for Decap CMS.
// It handles the callback from GitHub, exchanges the authorization code for an access token,
// and redirects back to Decap CMS with the necessary authentication information in the URL fragment.

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state'); // Crucial for security (CSRF protection)

  // Validate presence of authorization code
  if (!code) {
    console.error('Missing authorization code in GitHub callback.');
    return new Response('Authentication failed: Missing authorization code.', { status: 400 });
  }

  // Retrieve GitHub Client ID and Client Secret from Cloudflare Pages Environment Variables
  const GITHUB_CLIENT_ID = env.GITHUB_CLIENT_ID;
  const GITHUB_CLIENT_SECRET = env.GITHUB_CLIENT_SECRET;

  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
    console.error("Cloudflare Pages Environment Variables 'GITHUB_CLIENT_ID' or 'GITHUB_CLIENT_SECRET' are not set.");
    return new Response('Server configuration error: OAuth credentials missing.', { status: 500 });
  }

  // Define the GitHub token exchange endpoint
  const githubTokenUrl = 'https://github.com/login/oauth/access_token';

  try {
    // Exchange the authorization code for an access token with GitHub
    const tokenResponse = await fetch(githubTokenUrl, {
      method: 'POST',
      headers: {
        'Accept': 'application/json', // Request JSON response
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code: code,
        // redirect_uri is optional here if it matches the one registered in the GitHub App
        // and is not strictly required for the token exchange itself, but good practice
        // redirect_uri: `${url.origin}/admin/`, // Or your specific callback path if different
      }),
    });

    const tokenData = await tokenResponse.json();

    if (tokenData.error) {
      console.error('GitHub API Error (token exchange):', tokenData.error, tokenData.error_description);
      return new Response(`Authentication failed: GitHub Error - ${tokenData.error_description || tokenData.error}`, { status: 400 });
    }

    const accessToken = tokenData.access_token;
    const tokenType = tokenData.token_type || 'Bearer'; // Default to Bearer
    const expiresIn = tokenData.expires_in; // Optional, GitHub provides this for token expiration

    if (!accessToken) {
      console.error('GitHub token exchange successful but no access_token received.');
      return new Response('Authentication failed: Could not retrieve access token.', { status: 500 });
    }

    // Construct the redirect URL back to Decap CMS
    // Decap CMS expects the token and state in the URL fragment (#hash)
    const redirectFragment = new URLSearchParams();
    redirectFragment.append('access_token', accessToken);
    redirectFragment.append('token_type', tokenType);
    if (expiresIn) {
      redirectFragment.append('expires_in', expiresIn);
    }
    // Pass the state parameter back to Decap CMS for validation
    if (state) {
      redirectFragment.append('state', state);
    } else {
        // If state is missing, log a warning, as it's a security best practice to have it.
        console.warn('State parameter missing in GitHub authorization callback. CSRF protection may be compromised.');
    }

    // Redirect to the Decap CMS admin page with authentication details in the fragment
    const redirectUrl = `${url.origin}/admin/#${redirectFragment.toString()}`;

    return Response.redirect(redirectUrl, 302); // 302 Found for temporary redirect
  } catch (error) {
    console.error('Error during GitHub OAuth token exchange:', error);
    return new Response(`Authentication failed: Server error during token exchange.`, { status: 500 });
  }
}
