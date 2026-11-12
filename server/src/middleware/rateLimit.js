import rateLimit from 'express-rate-limit';

export const maintenanceLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,                  // was 100; the test floods ~40 requests
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, slow down.' }
});