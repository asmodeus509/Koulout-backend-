# FLEX TUPUP Backend - Deploy Ready

This package is prepared so Render can start the backend from the repository root:

- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/health`
- Root Directory: leave EMPTY on Render.

The backend also contains a mirrored `src/` copy so the source is preserved, but the production entry point is the root `server.js`.

Required Render environment variables:
- `DATABASE_URL`
- `JWT_SECRET`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `ADMIN_NAME=FLEX TUPUP Admin`
- `CORS_ORIGINS=*`
- `MAX_WALLET_DEPOSIT=500000`
- `MIN_WALLET_DEPOSIT=1`

Wallet flow:
POST `/api/wallet/deposits` -> admin GET `/api/admin/deposits` -> POST `/api/admin/deposits/:id/confirm` or `/refuse`.

The confirm route credits the user's wallet in PostgreSQL. No local-only wallet credit is used.
