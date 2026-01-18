// Vercel Serverless Function - Google OAuth Callback
import type { VercelRequest, VercelResponse } from '@vercel/node';

// Simple JWT creation using Web Crypto API (works in all environments)
async function createToken(payload: any, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  
  const base64UrlEncode = (str: string) => {
    return Buffer.from(str).toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };
  
  const headerEncoded = base64UrlEncode(JSON.stringify(header));
  const payloadWithExp = { ...payload, exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) };
  const payloadEncoded = base64UrlEncode(JSON.stringify(payloadWithExp));
  
  // Create signature using Node.js crypto (CommonJS style for Vercel)
  const { createHmac } = await import('node:crypto');
  const signature = createHmac('sha256', secret)
    .update(`${headerEncoded}.${payloadEncoded}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return `${headerEncoded}.${payloadEncoded}.${signature}`;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const { code } = req.query;
  
  // Use hardcoded URL for Vercel deployment
  const baseUrl = 'https://aether-workflow.vercel.app';
  const frontendUrl = baseUrl;
  
  if (!code) {
    return res.redirect(302, `${frontendUrl}?error=google_auth_failed&message=No+code+provided`);
  }

  try {
    const redirectUri = `${baseUrl}/api/auth/google/callback`;

    // Check if env vars exist
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      throw new Error('Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET env vars');
    }

    // Exchange code for access token
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code: code as string,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
      }),
    });

    const tokenData = await tokenResponse.json();
    
    if (!tokenData.access_token) {
      throw new Error(`Google token error: ${JSON.stringify(tokenData)}`);
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
    const token = await createToken(user, jwtSecret);

    // Redirect to frontend with token
    res.redirect(302, `${frontendUrl}?auth=success&token=${token}&provider=google`);

  } catch (error: any) {
    console.error('Google OAuth error:', error.message);
    res.redirect(302, `${frontendUrl}?error=google_auth_failed&message=${encodeURIComponent(error.message)}`);
  }
}
