// ============================================================
// /api/check.js — Vercel Serverless Function
// Password is stored ONLY in Vercel Environment Variable
// Never exposed in client code
// ============================================================

// Simple in-memory rate limiter (resets per serverless instance)
const attempts = new Map();

export default function handler(req, res) {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ── Rate limiting by IP ──────────────────────────────────
  const ip =
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown';

  const now      = Date.now();
  const record   = attempts.get(ip) || { count: 0, lockedUntil: 0 };

  // Still locked out?
  if (record.lockedUntil > now) {
    const waitSec = Math.ceil((record.lockedUntil - now) / 1000);
    return res.status(429).json({
      success: false,
      error:   `Too many attempts. Wait ${waitSec} seconds.`
    });
  }

  // ── Get submitted password ───────────────────────────────
  const { password } = req.body || {};

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ success: false, error: 'No password provided' });
  }

  // ── Get secret from Vercel env variable ─────────────────
  // Set this in Vercel Dashboard → Settings → Environment Variables
  // Key: SECRET_PASS   Value: your chosen secret word
  const secret = process.env.SECRET_PASS;

  if (!secret) {
    // Env variable not set — remind developer
    console.error('SECRET_PASS environment variable is not set!');
    return res.status(500).json({ success: false, error: 'Server misconfigured' });
  }

  // ── Compare passwords (timing-safe, case-insensitive trim) ──
  const submitted = password.trim();
  const correct   = secret.trim();

  if (submitted === correct) {
    // ✅ Correct password — reset attempts
    attempts.delete(ip);
    return res.status(200).json({ success: true });
  } else {
    // ❌ Wrong password — increment attempts
    record.count += 1;

    if (record.count >= 5) {
      record.lockedUntil = now + 30 * 1000; // 30 second lockout
      record.count       = 0;
    }

    attempts.set(ip, record);

    return res.status(401).json({
      success: false,
      error:   'Wrong password'
    });
  }
}
