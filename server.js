require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const { createClient } = require('@supabase/supabase-js');
const { requestOtp, verifyOtp, authMiddleware, requireRole, otpStore } = require('./src/auth');

const ENV = process.env.NODE_ENV || 'development';

// ─── Production Sanity Checks ──────────────────────────────────────────────────
if (ENV === 'production') {
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.includes('CHANGE')) {
        console.error('FATAL: JWT_SECRET is missing or insecure in PRODUCTION.');
        process.exit(1);
    }
    if (!process.env.APP_SECRET_KEY || process.env.APP_SECRET_KEY === 'default-secret') {
        console.error('FATAL: APP_SECRET_KEY is missing or insecure in PRODUCTION.');
        process.exit(1);
    }
}

const app = express();

// Trust Railway/Render/Heroku reverse proxy (needed for rate limiting to work correctly)
app.set('trust proxy', 1);

// 1. Basic HTTP Header Hardening & Sanitization
app.use(helmet());
app.use(express.json({ limit: '10mb' })); // 10MB to allow Base64 voice recording uploads

// Custom XSS sanitizer — strips HTML tags from all string values in req.body
// (replaces broken xss-clean library which is incompatible with Express v5+)
app.use((req, _res, next) => {
    function sanitize(obj) {
        if (typeof obj === 'string') return obj.replace(/<[^>]*>/g, '').trim();
        if (Array.isArray(obj)) return obj.map(sanitize);
        if (obj && typeof obj === 'object') {
            const clean = {};
            for (const key of Object.keys(obj)) clean[key] = sanitize(obj[key]);
            return clean;
        }
        return obj;
    }
    if (req.body) req.body = sanitize(req.body);
    next();
});

// 2. Environment-aware CORS (Includes Capacitor Mobile Native WebViews)
// Optionally allow a local dev origin for testing against production backend
// Set ALLOWED_LOCAL_ORIGIN=http://localhost:5173 in Railway env vars to enable
const extraOrigin = process.env.ALLOWED_LOCAL_ORIGIN;

const allowedOrigins = {
    development: ['http://localhost:5173', 'http://localhost:3000', 'capacitor://localhost', 'http://localhost', 'https://localhost'],
    uat:         ['https://uat.village-alert.app', 'capacitor://localhost', 'http://localhost', 'http://localhost:5173', 'https://localhost'],
    production:  ['https://village-alert.app', 'capacitor://localhost', 'http://localhost', 'http://localhost:5173', 'https://localhost'],
};

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (native mobile apps)
        if (!origin) return callback(null, true);

        const origins = allowedOrigins[ENV] || allowedOrigins.development;

        // Allow the configured extra origin (e.g. localhost for testing prod)
        if (extraOrigin && origin === extraOrigin) return callback(null, true);
        if (origins.includes(origin)) return callback(null, true);

        // Reject all other cross-origin requests
        console.warn(`[CORS] Blocked unauthorized origin: ${origin}`);
        callback(new Error(`CORS policy blocked origin.`));
    },
    credentials: true,
}));
console.log(`[SERVER] Starting in ${ENV.toUpperCase()} mode`);

// Internal memory mapping for auto-call cancellation
// Map<alertId, Map<userId, NodeJS.Timeout>>
const autoCallTimers = new Map();

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
app.locals.supabase = supabase; // Make available to global authMiddleware

// Initialize Firebase Admin (optional for local dev if missing creds)
const admin = require('firebase-admin');
const crypto = require('crypto');
try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
        const serviceAccount = JSON.parse(Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8'));
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        console.log("Firebase Admin initialized");
    } else {
        console.warn("FIREBASE_SERVICE_ACCOUNT_BASE64 not set. FCM pushes will be mocked.");
    }
} catch (e) {
    console.error("Failed to initialize Firebase Admin:", e);
}

// Basic health check
app.get('/health', (req, res) => {
    // Do not expose environment name in production (tells attackers rate-limiting is disabled)
    res.json({ status: 'ok', message: 'Gram Suraksha API is running', ...(ENV !== 'production' && { env: ENV }) });
});

// ─── Rate Limiting ────────────────────────────────────────────────────────────

// Global rate limiter for ALL /api/* routes (except auth which has strict limits)
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 mins
    max: 100,                 // 100 requests per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please try again later.' },
    skip: () => ENV === 'development',
});
app.use('/api/', globalLimiter);

// Auth specific strictly tuned limiters
const otpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many OTP requests from this IP. Please wait 15 minutes.' },
    skip: () => ENV === 'development', // No rate limit in local dev
});

const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many verification attempts. Please wait.' },
    skip: () => ENV === 'development',
});

// ─── Auth Routes (Public) ─────────────────────────────────────────────────────
app.post('/api/auth/request-otp', otpLimiter,    requestOtp);
app.post('/api/auth/verify-otp',  verifyLimiter, (req, res) => verifyOtp(req, res, supabase));

// Silent token refresh — keep users permanently signed in
app.post('/api/auth/refresh', authMiddleware, async (req, res) => {
    try {
        const jwt    = require('jsonwebtoken');
        const secret = process.env.JWT_SECRET || 'village-alert-system-dev-secret-CHANGE-IN-PROD';
        const expiry = process.env.JWT_EXPIRY  || '7d';

        // Fetch fresh user data in case role/approval changed since last login
        const { data: user } = await supabase
            .from('users')
            .select('*, villages!left(name)')
            .eq('id', req.user.sub)
            .single();

        if (!user) return res.status(404).json({ error: 'User not found.' });

        const newToken = jwt.sign(
            { sub: user.id, phone: user.phone, role: user.role, session_id: user.session_id, village_id: user.village_id },
            secret,
            { expiresIn: expiry, issuer: 'village-alert-system' }
        );

        console.log(`[AUTH] Silent refresh for ${user.phone} (${user.role})`);
        res.json({ success: true, token: newToken, user });
    } catch (e) {
        console.error('[REFRESH]', e);
        res.status(500).json({ error: 'Refresh failed.' });
    }
});

// Fetch all villages endpoint (public — needed for registration dropdowns)
app.get('/api/villages', async (req, res) => {
    try {
        const { data, error } = await supabase.from('villages').select('*').order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin: Create village (protected — admin only)
app.post('/api/villages', authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const { name, location, admin_id } = req.body;
        // In reality, you'd check if admin_id is an actual admin
        if (!name) return res.status(400).json({ error: 'Missing name' });
        
        const { data, error } = await supabase.from('villages').insert([{ name, location }]).select('*').single();
        if (error) throw error;
        res.status(201).json(data);
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin/Owner: Update Regions for a Village
app.put('/api/villages/:villageId/regions', authMiddleware, async (req, res) => {
    try {
        const { villageId } = req.params;
        const { regions } = req.body;
        
        if (req.user.role !== 'admin' && (req.user.role !== 'village_owner' || req.user.village_id !== villageId)) {
            return res.status(403).json({ error: 'Access denied.' });
        }

        const { data, error } = await supabase.from('villages').update({ regions }).eq('id', villageId).select('*').single();
        if (error) throw error;
        res.json(data);
    } catch (err) {
        console.error('[PUT /api/villages/:villageId/regions]', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin: Fetch all users mapped to villages (protected — admin only)
app.get('/api/users/pending', authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const { data, error } = await supabase.from('users').select('*, villages(name)').eq('role', 'village_owner').order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin: Fetch all active OTPs (since SMS is disabled via rollout)
app.get('/api/admin/otps', authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const otps = await otpStore.getAll();
        res.json(otps);
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin: Approve village_owner (protected — admin only)
app.put('/api/users/:id/approve', authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabase.from('users').update({ is_approved: true }).eq('id', id);
        if (error) throw error;
        res.json({ success: true, message: 'User approved' });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});



// Update FCM Token endpoint (protected)
app.post('/api/users/fcm-token', authMiddleware, async (req, res) => {
    try {
        const { user_id, fcm_token } = req.body;
        if (!user_id || !fcm_token) return res.status(400).json({ error: 'Missing req fields' });

        // Security: prevent a logged-in user from overwriting another user's FCM token
        if (user_id !== req.user.sub) {
            return res.status(403).json({ error: 'Cannot update another user\'s device token.' });
        }

        const { error } = await supabase.from('users').update({ fcm_token }).eq('id', user_id);
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ─── USER PROFILE ─────────────────────────────────────────────────────────────

app.put('/api/users/profile', authMiddleware, async (req, res) => {
    try {
        const { name, village_id } = req.body;
        const user_id = req.user.sub;
        
        // Fetch current user details to check if village is changing
        const { data: currentUser } = await supabase.from('users').select('village_id, role, guard_status').eq('id', user_id).single();

        let updateData = { name };
        
        // If they are changing village, auto-revoke guard status (to prevent carrying access to new village)
        if (village_id && currentUser && currentUser.village_id !== village_id) {
            updateData.village_id = village_id;
            if (currentUser.role === 'villager') {
                updateData.guard_status = 'none';
            }
        }

        const { error } = await supabase.from('users').update(updateData).eq('id', user_id);
        if (error) throw error;
        
        res.json({ success: true, message: 'Profile updated' });
    } catch (err) {
        console.error('Profile update error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ─── VILLAGE GUARDS ───────────────────────────────────────────────────────────

app.post('/api/guards/apply', authMiddleware, async (req, res) => {
    try {
        const user_id = req.user.sub;
        if (req.user.role !== 'villager') return res.status(400).json({ error: 'Only villagers can apply to be guards.' });

        const { error } = await supabase.from('users').update({ guard_status: 'pending' }).eq('id', user_id);
        if (error) throw error;
        
        res.json({ success: true, message: 'Application submitted successfully.' });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/guards/list/:villageId', authMiddleware, requireRole('village_owner', 'admin'), async (req, res) => {
    try {
        const { villageId } = req.params;
        // Owners can only view guards in their own village
        if (req.user.role === 'village_owner' && req.user.village_id !== villageId) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { data, error } = await supabase
            .from('users')
            .select('id, name, phone, guard_status, created_at')
            .eq('village_id', villageId)
            .eq('role', 'villager')
            .in('guard_status', ['pending', 'approved'])
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/guards/update', authMiddleware, requireRole('village_owner', 'admin'), async (req, res) => {
    try {
        const { target_user_id, status } = req.body;
        if (!['approved', 'none'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        // Must verify target user belongs to owner's village
        const { data: targetUser } = await supabase.from('users').select('village_id').eq('id', target_user_id).single();
        if (req.user.role === 'village_owner' && targetUser.village_id !== req.user.village_id) {
            return res.status(403).json({ error: 'Target user is not in your village.' });
        }

        const { error } = await supabase.from('users').update({ guard_status: status }).eq('id', target_user_id);
        if (error) throw error;

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Create Alert endpoint (protected — village_owner, admin, OR approved village_guard)
app.post('/api/alerts/send', authMiddleware, async (req, res) => {
    try {
        const { severity, message, audio_url, audio_base64, target_regions } = req.body;

        // Security: never trust client-sent sent_by or village_id.
        // Always derive them from the verified JWT so a modified client cannot spoof sender or village.
        const sent_by   = req.user.sub;
        const village_id = req.user.village_id;

        // Authorization logic for Guards
        if (req.user.role === 'villager') {
            const { data: freshUser } = await supabase.from('users').select('guard_status').eq('id', sent_by).single();
            if (!freshUser || freshUser.guard_status !== 'approved') {
                return res.status(403).json({ error: 'Access denied. You are not an approved Village Guard.' });
            }
        } else if (req.user.role !== 'village_owner' && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied. Only Owners, Admins, or Guards can dispatch alerts.' });
        }

        if (!village_id) {
            return res.status(403).json({ error: 'You are not associated with any village.' });
        }
        if (!severity || !message) {
            return res.status(400).json({ error: 'Missing required fields: severity and message' });
        }

        let final_audio_url = audio_url || null;

        // Upload Base64 Audio to Supabase Storage if provided
        if (audio_base64) {
            try {
                // Security: validate MIME type prefix before processing
                const mimeMatch = audio_base64.match(/^data:(audio\/\w+);base64,/);
                if (!mimeMatch) {
                    return res.status(400).json({ error: 'Invalid audio format. Only audio files are accepted.' });
                }
                const base64Data = audio_base64.replace(/^data:audio\/\w+;base64,/, "");
                const buffer = Buffer.from(base64Data, 'base64');
                const fileName = `alert_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.webm`;
                
                const { error: uploadError } = await supabase.storage
                    .from('alert-audio')
                    .upload(fileName, buffer, { contentType: 'audio/webm', upsert: true });
                    
                if (uploadError) throw uploadError;
                
                const { data: publicUrlData } = supabase.storage.from('alert-audio').getPublicUrl(fileName);
                final_audio_url = publicUrlData.publicUrl;
                console.log(`[Storage] Uploaded audio successfully: ${final_audio_url}`);
            } catch (audioErr) {
                console.error("Audio Upload Failed:", audioErr);
                return res.status(500).json({ error: 'Failed to upload voice recording to storage' });
            }
        }

        // Generate token
        const alertShortId = crypto.randomBytes(3).toString('hex'); // 6 chars
        const SECRET_KEY = process.env.APP_SECRET_KEY || 'default-secret';
        const signature = crypto.createHmac('sha256', SECRET_KEY).update(`${severity}-${alertShortId}`).digest('hex').slice(0, 4);
        const token = `VAS-${severity}-${alertShortId}-${signature}`;

        // Insert Alert
        const { data: alertData, error: alertError } = await supabase
            .from('alerts')
            .insert([{ village_id, sent_by, severity, message, audio_url: final_audio_url, token }])
            .select('*')
            .single();

        if (alertError) throw alertError;

        // Fetch all active users in village (include phone for SMS/call fallback layers)
        let query = supabase
            .from('users')
            .select('id, fcm_token, phone, region')
            .eq('village_id', village_id)
            .eq('is_active', true);

        if (target_regions && target_regions.length > 0 && !target_regions.includes('ALL')) {
            query = query.in('region', target_regions);
        }

        const { data: users, error: usersError } = await query;

        if (usersError) throw usersError;

        // Create Delivery records
        if (users && users.length > 0) {
            const deliveries = users.map(u => ({
                alert_id: alertData.id,
                user_id: u.id,
                channel: 'fcm',
                status: 'pending' // will be updated when actually successfully sent later or offline triggers it
            }));
            await supabase.from('deliveries').insert(deliveries);

            // Send FCM to users with token
            const fcmTokens = users.filter(u => u.fcm_token).map(u => u.fcm_token);
            if (process.env.ROLLOUT_PUSH !== 'true') {
                console.log(`[Push Disabled] Skipping FCM push via ROLLOUT_PUSH flag.`);
            } else if (fcmTokens.length > 0 && admin.apps.length > 0) {
                try {
                    const multicastMessage = {
                        tokens: fcmTokens,
                        data: { 
                            title: `${severity} ALERT`, 
                            body: message,
                            severity: String(severity), 
                            message: String(message), 
                            alert_id: String(alertData.id), 
                            audio_url: final_audio_url || '' 
                        },
                        android: { priority: 'high' },
                        apns: { payload: { aps: { sound: 'default' } } }
                    };
                    
                    const response = await admin.messaging().sendEachForMulticast(multicastMessage);
                    console.log(`Successfully sent ${response.successCount} FCM messages; ${response.failureCount} failed.`);
                    
                    // Handle stale FCM tokens
                    if (response.failureCount > 0) {
                        const failedTokens = [];
                        response.responses.forEach((resp, idx) => {
                            if (!resp.success) {
                                const errCode = resp.error?.code;
                                if (errCode === 'messaging/invalid-registration-token' || errCode === 'messaging/registration-token-not-registered') {
                                    failedTokens.push(fcmTokens[idx]);
                                }
                            }
                        });
                        if (failedTokens.length > 0) {
                           console.log(`Removing ${failedTokens.length} stale FCM tokens...`);
                           await supabase.from('users').update({ fcm_token: null }).in('fcm_token', failedTokens);
                        }
                    }
                } catch (fcmErr) {
                    console.error("FCM Send Error:", fcmErr);
                }
            } else {
                console.log("No FCM tokens or Firebase not configured. Skipping push.");
            }

            // Layer 2: SMS fallback (Offline-safe) — wrapped in try-catch
            try {
                const smsRecipients = users.map(u => u.phone);
                const smsBody = `[${token}] EMERGENCY: ${message} - Village Alert System. Do not reply.`;

                if (process.env.ROLLOUT_SMS === 'true' && process.env.MSG91_AUTH_KEY && smsRecipients.length > 0) {
                    console.log(`Sending SMS offline tokens to ${smsRecipients.length} users with MSG91...`);
                    // logic here...
                } else {
                    console.log(`[Flow] SMS layer (Flag: ${process.env.ROLLOUT_SMS})`);
                }
            } catch (err) { console.error("[Layer 2 Error]", err.message); }

            // Layer 3: Auto Call (Exotel) — wrapped in try-catch
            try {
                if (process.env.ROLLOUT_CALL === 'true') {
                    console.log("Scheduling Exotel Auto-call tasks in 90 seconds for unacknowledged users.");
                    const alertTimers = new Map();
                    users.forEach(u => {
                        const timerId = setTimeout(async () => {
                            try {
                                const { data: deliveryCheck } = await supabase
                                    .from('deliveries')
                                    .select('status')
                                    .eq('alert_id', alertData.id)
                                    .eq('user_id', u.id)
                                    .single();

                                if (deliveryCheck && deliveryCheck.status !== 'acked') {
                                    console.log(`[Exotel Auto-Call] Initiating call to User ${u.id} (${u.phone}).`);
                                    await supabase.from('deliveries')
                                        .update({ channel: 'call', status: 'sent' })
                                        .eq('alert_id', alertData.id)
                                        .eq('user_id', u.id);
                                }
                            } catch (e) { console.error("Exotel Timeout error", e) }
                        }, 90 * 1000);
                        alertTimers.set(u.id, timerId);
                    });
                    autoCallTimers.set(alertData.id, alertTimers);
                } else {
                    console.log(`[Flow] Call layer (Flag: ${process.env.ROLLOUT_CALL})`);
                }
            } catch (err) { console.error("[Layer 3 Error]", err.message); }

            // Layer 4: WhatsApp broadcast (WATI / Twilio Fallback)
            try {
                if (process.env.WATI_AUTH_TOKEN) {
                    console.log(`Sending WhatsApp broadcast...`);
                } else {
                    console.log("[Flow] WhatsApp layer (WATI_AUTH_TOKEN not set)");
                }
            } catch (err) { console.error("[Layer 4 Error]", err.message); }
        }

        res.status(201).json({ 
            message: 'Alert sent successfully', 
            alert: alertData,
            total_users: users ? users.length : 0
        });
    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * GET /api/alerts/:id/stats
 * Real-time telemetry for an alert.
 * Returns: { total, acked, fcm, sms, call }
 */
app.get('/api/alerts/:id/stats', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;

        // Query all delivery records for this alert to calculate real-time stats
        const { data: deliveries, error } = await supabase
            .from('deliveries')
            .select('status, channel')
            .eq('alert_id', id);

        if (error) throw error;

        // Calculate counts based on current delivery states
        const stats = {
            total: deliveries.length,
            acked: deliveries.filter(d => d.status === 'acked').length,
            fcm:   deliveries.filter(d => d.channel === 'fcm' || (d.channel === 'sms' && d.status === 'pending')).length, // default fallback
            sms:   deliveries.filter(d => d.channel === 'sms').length,
            call:  deliveries.filter(d => d.channel === 'call').length,
        };

        res.json(stats);
    } catch (err) {
        console.error('[STATS] Server error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Fetch Alert History for a Village
app.get('/api/alerts/village/:villageId', authMiddleware, async (req, res) => {
    try {
        const { villageId } = req.params;

        // Security: admins can view any village; others can only view their own village
        if (req.user.role !== 'admin' && req.user.village_id !== villageId) {
            return res.status(403).json({ error: 'You can only view alerts for your own village.' });
        }

        const { data, error } = await supabase
            .from('alerts')
            .select(`
                *,
                sender:users!sent_by(name, role, guard_status)
            `)
            .eq('village_id', villageId)
            .order('sent_at', { ascending: false })
            .limit(20);
            
        if (error) throw error;
        res.json(data);
    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Retract Alert endpoint (protected — village_owner or admin)
app.put('/api/alerts/:id/retract', authMiddleware, requireRole('village_owner', 'admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const { user_id } = req.body; // should be the admin handling it
        
        // 1. Get the alert to find its village_id
        const { data: alertData, error: fetchErr } = await supabase.from('alerts').select('village_id').eq('id', id).single();
        if (fetchErr) throw fetchErr;

        // 2. Mark alert as resolved
        const { error } = await supabase.from('alerts').update({ resolved_at: new Date().toISOString() }).eq('id', id);
        if (error) throw error;
        
        // 3. Cancel all pending Exotel calls for this alert
        if (autoCallTimers.has(id)) {
            const userTimers = autoCallTimers.get(id);
            userTimers.forEach(timer => clearTimeout(timer));
            autoCallTimers.delete(id);
            console.log(`[RETRACTED] Cancelled all pending auto-calls for alert ${id}.`);
        }

        // 4. Send Silent Push to stop ringing on all devices
        try {
            if (admin.apps.length > 0) {
                const { data: users } = await supabase.from('users').select('fcm_token').eq('village_id', alertData.village_id).neq('fcm_token', null);
                if (users && users.length > 0) {
                    const tokens = users.map(u => u.fcm_token);
                    if (tokens.length > 0) {
                        const multicastMessage = {
                            tokens,
                            data: { 
                                action: 'abort', 
                                alert_id: String(id),
                                title: 'Alert Resolved',
                                body: 'The emergency has been resolved.'
                            }
                        };
                        await admin.messaging().sendEachForMulticast(multicastMessage);
                        console.log(`[Abort] Sent silence signal to ${tokens.length} devices.`);
                    }
                }
            }
        } catch (pushErr) { console.error("Abort push failed", pushErr); }

        res.json({ success: true, message: 'Alert retracted successfully. All pending automation stopped.' });
    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Acknowledge endpoint (protected — any authenticated user)
app.post('/api/alerts/ack/:alertId', authMiddleware, async (req, res) => {
    try {
        const { alertId } = req.params;
        const { user_id } = req.body;

        if (!user_id) return res.status(400).json({ error: 'user_id required' });

        // Security: only allow users to acknowledge their own delivery record
        // Prevents attackers from marking other villagers as 'safe' to suppress auto-calls
        if (user_id !== req.user.sub) {
            return res.status(403).json({ error: 'You can only acknowledge your own alerts.' });
        }

        const { error } = await supabase
            .from('deliveries')
            .update({ status: 'acked', acked_at: new Date().toISOString() })
            .eq('alert_id', alertId)
            .eq('user_id', user_id);

        if (error) throw error;

        // Cancel the pending Exotel call for this user if it hasn't fired yet!
        if (autoCallTimers.has(alertId)) {
            const userTimers = autoCallTimers.get(alertId);
            if (userTimers.has(user_id)) {
                clearTimeout(userTimers.get(user_id));
                userTimers.delete(user_id);
                console.log(`[Cancelled] Auto-call aborted for User ${user_id} on alert ${alertId} due to fast ACK.`);
            }
        }

        res.json({ success: true, message: 'Alert acknowledged' });
    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
