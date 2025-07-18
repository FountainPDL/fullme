# FountainScan Node.js + Supabase Backend

## Setup

1. Copy `.env.example` to `.env` and fill in your Supabase credentials.
2. Run `npm install`
3. Start the server: `npm run dev` (for development) or `npm start`

## API Endpoints

- `POST /api/report` — Submit a suspicious site report (`{ url, reason }`)
- `GET /api/reports` — Get all submitted reports

## Supabase Table Example

Create a `reports` table with columns:
- `id` (uuid, primary key, default: uuid_generate_v4())
- `url` (text)
- `reason` (text)
- `created_at` (timestamp, default: now())