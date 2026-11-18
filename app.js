// SSO demo: a mini "enterprise app" that delegates login to Google (OpenID Connect).
// Run two copies on different ports to see single sign-on:
//   node app.js 3000 "Jira (App A)"
//   node app.js 4000 "Wiki (App B)"

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const PORT = Number(process.argv[2]) || 3000;
const APP_NAME = process.argv[3] || 'App A';

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = `http://localhost:${PORT}/auth/callback`;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('Missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET in .env');
  process.exit(1);
}

// Google library: exchanges the code for tokens and verifies the ID token signature.
const google = new OAuth2Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

const app = express();

// Each app keeps its OWN local session (cookie name differs per port,
// because browsers share localhost cookies across ports).
app.use(session({
  name: `sid_${PORT}`,
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
}));

const page = (body) => `<!doctype html><html><head><meta charset="utf-8">
<title>${APP_NAME}</title>
<style>body{font-family:system-ui;max-width:640px;margin:60px auto;padding:0 16px}
a.btn{display:inline-block;padding:10px 16px;background:#1a73e8;color:#fff;border-radius:6px;text-decoration:none}
img{border-radius:50%;vertical-align:middle;margin-right:10px}
pre{background:#f4f4f4;padding:12px;border-radius:6px;overflow:auto}</style>
</head><body><h1>${APP_NAME}</h1>${body}</body></html>`;

// Home: shows who is logged in, or a login button.
app.get('/', (req, res) => {
  const u = req.session.user;
  if (!u) {
    return res.send(page(`<p>You are not logged in to this app.</p>
      <a class="btn" href="/login">Sign in with Google</a>`));
  }
  res.send(page(`
    <p><img src="${u.picture}" width="48" height="48" alt="">
       Welcome <b>${u.name}</b> (${u.email})</p>
    <p>Identity verified by Google. Claims from the ID token:</p>
    <pre>${JSON.stringify(u, null, 2)}</pre>
    <a href="/logout">Log out of ${APP_NAME}</a>`));
});

// Step 1: redirect the user to Google (the Identity Provider).
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex'); // protects against CSRF
  const nonce = crypto.randomBytes(16).toString('hex'); // protects against token replay
  req.session.state = state;
  req.session.nonce = nonce;

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',            // Authorization Code flow
    scope: 'openid email profile',    // "openid" = OpenID Connect
    state,
    nonce,
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// Step 2: Google sends the user back here with a one-time code.
app.get('/auth/callback', async (req, res) => {
  try {
    if (!req.query.code || req.query.state !== req.session.state) {
      return res.status(400).send('Invalid state or missing code');
    }

    // Step 3: exchange the code for tokens (server-to-server, uses the client secret).
    const { tokens } = await google.getToken(req.query.code);

    // Step 4: verify the ID token (signature, issuer, audience, expiry).
    const ticket = await google.verifyIdToken({
      idToken: tokens.id_token,
      audience: CLIENT_ID,
    });
    const claims = ticket.getPayload();
    if (claims.nonce !== req.session.nonce) {
      return res.status(400).send('Invalid nonce');
    }

    // Step 5: create the local session for this app.
    req.session.user = {
      sub: claims.sub,          // Google's unique user id
      email: claims.email,
      email_verified: claims.email_verified,
      name: claims.name,
      picture: claims.picture,
      issuer: claims.iss,
    };
    delete req.session.state;
    delete req.session.nonce;
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Login failed: ' + err.message);
  }
});

// Logs out of THIS app only (the Google session stays active).
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.listen(PORT, () => {
  console.log(`${APP_NAME} running at http://localhost:${PORT}`);
});
