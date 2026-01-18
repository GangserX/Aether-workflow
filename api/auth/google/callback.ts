// Vercel Serverless Function - Google OAuth Callback
import type { VercelRequest, VercelResponse } from '@vercel/node';

// Simple JWT creation (for serverless - no external deps needed)
function createToken(payload: any, secret: string): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  
  const base64UrlEncode = (obj: any) => {
    const str = JSON.stringify(obj);
    const base64 = Buffer.from(str).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };
  
  const headerEncoded = base64UrlEncode(header);
  const payloadEncoded = base64UrlEncode({ ...payload, exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) });
  
  // For simplicity, we'll create a basic signature
  const crypto = require('crypto');
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${headerEncoded}.${payloadEncoded}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return `${headerEncoded}.${payloadEncoded}.${signature}`;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const { code } = req.query;
  
  // Determine the base URL dynamically
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const baseUrl = `${protocol}://${host}`;
  const frontendUrl = process.env.FRONTEND_URL || baseUrl;
  
  if (!code) {
    return res.redirect(302, `${frontendUrl}?error=google_auth_failed&message=No+code+provided`);
  }

  try {
    const redirectUri = `${baseUrl}/api/auth/google/callback`;

    // Exchange code for access token
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
      }),
    });

    const tokenData = await tokenResponse.json();
    
    if (!tokenData.access_token) {
      throw new Error('No access token received from Google');
    }

    // Get user info from Google
    const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    const googleUser = await userResponse.json();

    // Create user object
    const user = {
      id: `google_${googleUser.id}`,
      email: googleUser.email,
      name: googleUser.name,
      avatar: googleUser.picture,
      picture: googleUser.picture,
      provider: 'google',
      providerId: googleUser.id,
    };

    // Create JWT token
    const jwtSecret = process.env.JWT_SECRET || 'aether-jwt-secret-vercel';
    const token = createToken(user, jwtSecret);

    // Redirect to frontend with token
    res.redirect(302, `${frontendUrl}?auth=success&token=${token}&provider=google`);

  } catch (error: any) {
    console.error('Google OAuth error:', error.message);
    res.redirect(302, `${frontendUrl}?error=google_auth_failed&message=${encodeURIComponent(error.message)}`);
  }
}
