import { doubleCsrf } from 'csrf-csrf';

// Double-submit-cookie CSRF protection (csrf-csrf).
//  - The server signs a token bound to the user's session (the auth JWT cookie)
//    and sets it in a cookie; the same token is also returned in the JSON body.
//  - A write must echo the token in the `x-csrf-token` header AND carry the cookie.
//    A cross-site page can make the browser send the cookie, but it cannot read the
//    token (same-origin policy) nor set a custom header without a CORS preflight
//    that our locked-down CORS config refuses.
const {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind the token to the session: a token minted for one user is useless for another.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf_token',
  cookieOptions: {
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    httpOnly: true,
    path: '/'
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // GET / HEAD / OPTIONS are "safe" methods and stay exempt (library default).
  // login/register run before any session exists, so there is nothing to forge yet.
  skipCsrfProtection: (req) =>
    req.path === '/api/auth/login' || req.path === '/api/auth/register',
  errorConfig: { statusCode: 403, message: 'Invalid or missing CSRF token', code: 'EBADCSRFTOKEN' }
});

export { doubleCsrfProtection, invalidCsrfTokenError };

// GET /api/csrf-token — the client calls this and echoes the token on every write.
export function csrfTokenHandler(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res) });
}