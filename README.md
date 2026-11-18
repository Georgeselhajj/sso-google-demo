# SSO demo with Google as the Identity Provider

Two small "enterprise apps" (App A = Jira, App B = Wiki) that don't store any
passwords. Both rely on Google to authenticate the user using **OpenID Connect**
(Authorization Code flow).

## 1. Set up Google (once)
1. Go to https://console.cloud.google.com and create a project.
2. **APIs & Services → OAuth consent screen**: choose *External*, fill in the app name
   and your email, and add your Gmail as a *test user*.
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**
   - Type: *Web application*
   - Authorized redirect URIs (add both):
     - `http://localhost:3000/auth/callback`
     - `http://localhost:4000/auth/callback`
4. Copy the Client ID and Client Secret.

## 2. Run
```bash
npm install
cp .env.example .env      # then paste your Client ID / Secret into .env
npm run app-a             # terminal 1 -> http://localhost:3000
npm run app-b             # terminal 2 -> http://localhost:4000
```

## 3. Demo scenario (for the presentation)
1. Open App A and click **Sign in with Google**. Enter your Google password.
2. Open App B and click **Sign in with Google**. **No password is asked:** Google
   already has a session, so you're logged in straight away. That is SSO.
3. Show the ID token claims on the page (`iss`, `sub`, `email`...). The app trusts
   them because it verified Google's signature.

## Flow
```
User ──> App A /login ──redirect──> Google (login once)
                                       │
App A /auth/callback <──code──────────┘
App A ──code + secret──> Google token endpoint ──> ID token (JWT)
App A verifies JWT signature ──> creates local session
```
`state` protects against CSRF and `nonce` protects against token replay.
