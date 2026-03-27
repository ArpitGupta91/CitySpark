import jwt from 'jsonwebtoken';

function getSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('JWT_SECRET must be set in production');
    }
    return 'cityspark-dev-only-not-for-production';
  }
  return s;
}

function getExpiresIn() {
  const raw = String(process.env.JWT_EXPIRES_IN ?? '7d').trim();
  if (!raw) return '7d';

  // Accept plain seconds (e.g. "3600") as a number.
  if (/^\d+$/.test(raw)) {
    return Number(raw);
  }

  // Accept common time-span formats (e.g. "7d", "20h", "60m").
  const normalized = raw.replace(/\s+/g, '').toLowerCase();
  if (/^\d+(ms|s|m|h|d|w|y)$/.test(normalized)) {
    return normalized;
  }

  console.warn(`Invalid JWT_EXPIRES_IN value "${raw}". Falling back to "7d".`);
  return '7d';
}

export function signAccessToken(userDoc) {
  const payload = {
    sub: userDoc._id.toString(),
    email: userDoc.email,
    name: userDoc.name,
    role: userDoc.role,
  };
  return jwt.sign(payload, getSecret(), { expiresIn: getExpiresIn() });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, getSecret());
}
