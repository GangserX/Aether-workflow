// Vercel Serverless Function - GitHub OAuth Callback
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
    return res.redirect(302, `${frontendUrl}?error=github_auth_failed&message=No+code+provided`);
  }

  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
      }),
    });

    const tokenData = await tokenResponse.json();
    
    if (!tokenData.access_token) {
      throw new Error('No access token received from GitHub');
    }

    // Get user info from GitHub
    const userResponse = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    const githubUser = await userResponse.json();

    // Get user email (might be private)
    const emailsResponse = await fetch('https://api.github.com/user/emails', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    const emailsData = await emailsResponse.json();
    const primaryEmail = emailsData.find((e: any) => e.primary)?.email || 
                         emailsData[0]?.email ||
                         `${githubUser.login}@github.local`;

    // Create user object
    const user = {
      id: `github_${githubUser.id}`,
      email: primaryEmail,
      name: githubUser.name || githubUser.login,
      avatar: githubUser.avatar_url,
      picture: githubUser.avatar_url,
      provider: 'github',
      providerId: githubUser.id.toString(),
    };

    // Create JWT token
    const jwtSecret = process.env.JWT_SECRET || 'aether-jwt-secret-vercel';
    const token = createToken(user, jwtSecret);

    // Redirect to frontend with token
    res.redirect(302, `${frontendUrl}?auth=success&token=${token}&provider=github`);

  } catch (error: any) {
    console.error('GitHub OAuth error:', error.message);
    res.redirect(302, `${frontendUrl}?error=github_auth_failed&message=${encodeURIComponent(error.message)}`);
  }
}
