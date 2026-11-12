import rateLimit from 'express-rate-limit';

// Throttle the maintenance feature: one client may make at most 30 requests per
// minute. Beyond that the server answers 429 instead of doing more DB work.
export const maintenanceLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later.' }
});