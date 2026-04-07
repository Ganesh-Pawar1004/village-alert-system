-- Villages
CREATE TABLE IF NOT EXISTS villages (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  location    TEXT,
  regions     TEXT[] DEFAULT '{}',         -- Array of valid regions specified by the Village Owner
  created_at  TIMESTAMP DEFAULT NOW()
);

-- Users (admins + village_owners + villagers)
CREATE TABLE IF NOT EXISTS users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone       TEXT UNIQUE NOT NULL,
  name        TEXT NOT NULL,
  village_id  UUID REFERENCES villages(id),
  role        TEXT CHECK (role IN ('admin', 'village_owner', 'villager')) DEFAULT 'villager',
  session_id  UUID,                        -- tracks the single active device
  fcm_token   TEXT,                        -- updated on every app open
  is_active   BOOLEAN DEFAULT true,
  is_approved BOOLEAN DEFAULT false,       -- only village_owners need approval
  guard_status TEXT DEFAULT 'none',        -- 'none', 'pending', 'approved'
  region      TEXT,                        -- User's selected sub-region inside the village
  created_at  TIMESTAMP DEFAULT NOW()
);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  village_id  UUID REFERENCES villages(id),
  sent_by     UUID REFERENCES users(id),
  severity    TEXT CHECK (severity IN ('RED', 'YELLOW', 'GREEN')),
  message     TEXT NOT NULL,               -- short text message
  audio_url   TEXT,                        -- Cloudinary URL (optional)
  token       TEXT NOT NULL,               -- signed SMS token
  sent_at     TIMESTAMP DEFAULT NOW(),
  resolved_at TIMESTAMP                    -- when GREEN / all-clear sent
);

-- Delivery tracking (one row per user per alert)
CREATE TABLE IF NOT EXISTS deliveries (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id    UUID REFERENCES alerts(id),
  user_id     UUID REFERENCES users(id),
  channel     TEXT CHECK (channel IN ('fcm', 'sms', 'call')),
  status      TEXT CHECK (status IN ('pending', 'sent', 'delivered', 'acked', 'failed')),
  sent_at     TIMESTAMP,
  acked_at    TIMESTAMP,                   -- when user tapped "I received"
  UNIQUE(alert_id, user_id)
);

-- Row Level Security (RLS) setup (optional but recommended)
ALTER TABLE villages ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE deliveries ENABLE ROW LEVEL SECURITY;

-- Note: You should configure proper RLS policies in the Supabase dashboard based on your auth strategy.
-- For local development / anon key usage, you can use these permissive policies:

-- Users table policies
CREATE POLICY "Enable read access for all users" ON "public"."users" FOR SELECT USING (true);
CREATE POLICY "Enable insert for all users" ON "public"."users" FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update for all users" ON "public"."users" FOR UPDATE USING (true) WITH CHECK (true);

-- Villages table policies
CREATE POLICY "Enable read access for all villages" ON "public"."villages" FOR SELECT USING (true);
CREATE POLICY "Enable insert for all villages" ON "public"."villages" FOR INSERT WITH CHECK (true);

-- Alerts table policies
CREATE POLICY "Enable read access for all alerts" ON "public"."alerts" FOR SELECT USING (true);
CREATE POLICY "Enable insert for all alerts" ON "public"."alerts" FOR INSERT WITH CHECK (true);

-- Deliveries table policies
CREATE POLICY "Enable read access for all deliveries" ON "public"."deliveries" FOR SELECT USING (true);
CREATE POLICY "Enable insert for all deliveries" ON "public"."deliveries" FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update for all deliveries" ON "public"."deliveries" FOR UPDATE USING (true) WITH CHECK (true);
