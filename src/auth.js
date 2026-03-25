/**
 * auth.js - Production-grade OTP + JWT Authentication Module
 *
 * OTP Store Strategy (environment-aware):
 *   - DEVELOPMENT: in-memory Map (no Redis needed locally)
 *   - UAT / PRODUCTION: Redis via ioredis for distributed, persistent OTP state
 */

const jwt    = require('jsonwebtoken');
const Redis  = require('ioredis');
const { randomInt } = require('crypto');

const ENV        = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET || 'village-alert-system-dev-secret-CHANGE-IN-PROD';
const JWT_EXPIRY = process.env.JWT_EXPIRY  || '7d';

const OTP_TTL_SECONDS  = 5 * 60;       // 5 minutes
const OTP_RESEND_WAIT  = 60;            // seconds
const MAX_ATTEMPTS     = 30;           // user-requested 30 attempts
const LOCKOUT_SECONDS  = 15 * 60;      // 15 minutes lockout after failure

// ─── OTP Store (Redis or in-memory) ───────────────────────────────────────────

let redis = null;

if (ENV !== 'development' && process.env.REDIS_URL) {
    redis = new Redis(process.env.REDIS_URL, {
        retryStrategy: (times) => Math.min(times * 100, 3000),
        lazyConnect: true,
    });
    redis.on('connect', () => console.log('[Redis] Connected to OTP store'));
    redis.on('error',   (e) => console.error('[Redis] Error:', e.message));
} else {
    console.log(`[AUTH] Using in-memory OTP store (${ENV} mode)`);
}

// Unified interface: get/set/del OTP records regardless of store backend
const otpStore = {
    async get(phone) {
        if (redis) {
            const raw = await redis.get(`otp:${phone}`);
            return raw ? JSON.parse(raw) : null;
        }
        return memStore.get(phone) || null;
    },
    async set(phone, record) {
        if (redis) {
            await redis.set(`otp:${phone}`, JSON.stringify(record), 'EX', OTP_TTL_SECONDS + OTP_RESEND_WAIT);
        } else {
            memStore.set(phone, record);
            // Auto-expire from memory
            setTimeout(() => memStore.delete(phone), (OTP_TTL_SECONDS + OTP_RESEND_WAIT) * 1000);
        }
    },
    async del(phone) {
        if (redis) {
            await redis.del(`otp:${phone}`);
        } else {
            memStore.delete(phone);
        }
    },
    async update(phone, record) {
        // Update in place; Redis: preserve remaining TTL approx
        await this.set(phone, record);
    },
    async setLockout(phone) {
        if (redis) {
            await redis.set(`lockout:${phone}`, 'true', 'EX', LOCKOUT_SECONDS);
        } else {
            memLockouts.set(phone, Date.now() + LOCKOUT_SECONDS * 1000);
            setTimeout(() => memLockouts.delete(phone), LOCKOUT_SECONDS * 1000);
        }
    },
    async isLockedOut(phone) {
        if (redis) {
            return await redis.get(`lockout:${phone}`) === 'true';
        }
        const expiry = memLockouts.get(phone);
        return expiry && Date.now() < expiry;
    },
    async getAll() {
        const otps = [];
        if (redis) {
            const keys = await redis.keys('otp:*');
            for (const key of keys) {
                const raw = await redis.get(key);
                if (raw) otps.push({ phone: key.replace('otp:', ''), ...JSON.parse(raw) });
            }
        } else {
            for (const [phone, record] of memStore.entries()) {
                otps.push({ phone, ...record });
            }
        }
        return otps.sort((a, b) => b.sentAt - a.sentAt);
    }
};
const memStore = new Map(); // fallback for DEV
const memLockouts = new Map();

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateOtp() {
    return String(randomInt(100000, 999999));
}

async function sendOtpViaSms(phone, otp) {
    const smsBody = `[Village Alert] Your OTP is ${otp}. Valid for 5 minutes. Do NOT share.`;

    // 1. DEV mode bypass
    if (ENV === 'development') {
        console.log(`\n========================================`);
        console.log(` [DEV OTP]  Phone : ${phone}`);
        console.log(` [DEV OTP]  OTP   : ${otp}`);
        console.log(`========================================\n`);
        return { mocked: true, reason: 'development' };
    }

    // 2. Rollout feature flag check
    if (process.env.ROLLOUT_SMS !== 'true') {
        console.log(`[SMS Disabled] OTP for ${phone} generated but SMS skipped via ROLLOUT_SMS flag.`);
        return { mocked: true, reason: 'rollout_disabled' };
    }

    if (!process.env.MSG91_AUTH_KEY) {
        throw new Error('MSG91_AUTH_KEY not configured for non-dev environment');
    }

    const res = await fetch('https://api.msg91.com/api/v5/flow/', {
        method: 'POST',
        headers: { authkey: process.env.MSG91_AUTH_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({
            template_id: process.env.MSG91_OTP_TEMPLATE_ID,
            short_url: '0',
            recipients: [{ mobiles: `91${phone}`, otp }],
        }),
    });

    const result = await res.json();
    if (!res.ok || result.type !== 'success') {
        throw new Error(`MSG91: ${result.message || 'Unknown error'}`);
    }
    return { mocked: false };
}

// ─── Route Handlers ───────────────────────────────────────────────────────────

/**
 * POST /api/auth/request-otp
 * Body: { phone: "9876543210" }
 * Public — no auth required
 */
async function requestOtp(req, res) {
    const { phone } = req.body;

    if (!phone || !/^\d{10}$/.test(phone)) {
        return res.status(400).json({ error: 'A valid 10-digit Indian mobile number is required.' });
    }

    if (await otpStore.isLockedOut(phone)) {
        return res.status(429).json({ error: 'Account locked for 15 minutes due to too many failed attempts.' });
    }

    const now = Date.now();
    const existing = await otpStore.get(phone);

    if (existing && (now - existing.sentAt) < (OTP_RESEND_WAIT * 1000)) {
        const waitSec = Math.ceil((OTP_RESEND_WAIT * 1000 - (now - existing.sentAt)) / 1000);
        return res.status(429).json({ error: `Wait ${waitSec}s before requesting another OTP.` });
    }

    const otp = generateOtp();
    const record = { otp, sentAt: now, expiresAt: now + OTP_TTL_SECONDS * 1000, attempts: 0 };
    await otpStore.set(phone, record);

    try {
        const result = await sendOtpViaSms(phone, otp);
        return res.json({
            success: true,
            message: 'OTP sent to your mobile number.',
            ...(ENV === 'development' && { dev_otp: otp }),
        });
    } catch (e) {
        await otpStore.del(phone);
        console.error('[OTP] Send failed:', e.message);
        return res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
    }
}

/**
 * POST /api/auth/verify-otp
 * Body: { phone, otp, name?, village_id?, role? }
 * Public — returns JWT on success
 */
async function verifyOtp(req, res, supabase) {
    const { phone, otp, name, village_id, role } = req.body;

    if (!phone || !otp) {
        return res.status(400).json({ error: 'phone and otp are required.' });
    }

    // ─── Super Admin Static Bypass ──────────────────────────────────────────────
    // Crucial for when SMS is rolled out (disabled) in production
    const isSuperAdminBypass = 
        process.env.SUPERADMIN_PHONE && 
        process.env.SUPERADMIN_OTP && 
        phone === process.env.SUPERADMIN_PHONE && 
        String(otp) === process.env.SUPERADMIN_OTP;

    if (!isSuperAdminBypass) {
        if (await otpStore.isLockedOut(phone)) {
            return res.status(429).json({ error: 'Account locked for 15 minutes due to too many failed attempts.' });
        }
        const record = await otpStore.get(phone);

        if (!record) {
            return res.status(400).json({ error: 'OTP expired or not requested. Ask for a new one.' });
        }

        if (Date.now() > record.expiresAt) {
            await otpStore.del(phone);
            return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
        }

        if (record.otp !== String(otp)) {
            record.attempts += 1;
            if (record.attempts >= MAX_ATTEMPTS) {
                await otpStore.del(phone);
                await otpStore.setLockout(phone);
                return res.status(429).json({ error: 'Too many failed attempts. Locked for 15 minutes.' });
            }
            await otpStore.update(phone, record);
            const remaining = MAX_ATTEMPTS - record.attempts;
            return res.status(401).json({ error: `Incorrect OTP. ${remaining} attempt(s) left.` });
        }

        // ✓ Valid — but DO NOT consume yet. Wait until user record is verified/created.
    } // end bypass check

    // Upsert user
    let { data: user } = await supabase
        .from('users')
        .select('*, villages!left(name)')
        .eq('phone', phone)
        .single();

    if (!user) {
        // First time — register
        if (!name) return res.status(400).json({ error: 'name is required for first-time setup.' });
        if (role !== 'admin' && !village_id) return res.status(400).json({ error: 'village_id is required.' });

        const is_approved = role === 'villager' || role === 'admin';
        const { data: newUser, error } = await supabase
            .from('users')
            .insert([{ phone, name, village_id: village_id || null, role: role || 'villager', is_approved }])
            .select('*, villages!left(name)')
            .single();

        if (error) {
            console.error('[AUTH] insert error:', error);
            return res.status(500).json({ error: 'Failed to create account.' });
        }
        user = newUser;
    }

    // Success — Consume OTP now
    if (!isSuperAdminBypass) {
        await otpStore.del(phone);
    }

    // Sign JWT
    const token = jwt.sign(
        { sub: user.id, phone: user.phone, role: user.role, village_id: user.village_id },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY, issuer: 'village-alert-system' }
    );

    console.log(`[AUTH] ✓ ${user.phone} (${user.role}) authenticated`);
    res.json({ success: true, token, user });
}

// ─── JWT Middleware ────────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
    const header = req.headers['authorization'];
    if (!header?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization token required.' });
    }
    try {
        req.user = jwt.verify(header.split(' ')[1], JWT_SECRET, { issuer: 'village-alert-system' });
        next();
    } catch (e) {
        const msg = e.name === 'TokenExpiredError' ? 'Session expired. Please log in again.' : 'Invalid token.';
        return res.status(401).json({ error: msg });
    }
}

function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ error: `Access denied. Required: ${roles.join(' or ')}` });
        }
        next();
    };
}

module.exports = { requestOtp, verifyOtp, authMiddleware, requireRole, otpStore };
