import { doubleCsrf } from 'csrf-csrf';

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind the token to the session cookie (JWT)
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf-token',   // no __Host- prefix: needs HTTPS, we're on http://localhost
  cookieOptions: { sameSite: 'lax', secure: false, httpOnly: true, path: '/' },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
  // GET / HEAD / OPTIONS are ignored by default
});

// Pre-auth routes: no session exists yet, so there is nothing to forge.
const EXEMPT = new Set(['/api/auth/login', '/api/auth/register']);

export function csrfProtection(req, res, next) {
  if (EXEMPT.has(req.originalUrl.split('?')[0])) return next();
  return doubleCsrfProtection(req, res, next);
}

export function csrfTokenHandler(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res) });
}