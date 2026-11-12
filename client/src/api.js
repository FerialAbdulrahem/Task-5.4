import axios from 'axios'

// `withCredentials: true` sends the httpOnly auth cookie with every request.
// Because the browser also does that for forged cross-site requests, every
// state-changing request additionally carries a CSRF token in a header, which a
// malicious site can neither read nor set.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const SAFE = ['get', 'head', 'options']
const PRE_AUTH = ['/auth/login', '/auth/register']
let csrfToken = null

async function getCsrfToken() {
  if (!csrfToken) {
    const res = await api.get('/csrf-token')
    csrfToken = res.data.csrfToken
  }
  return csrfToken
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  if (SAFE.includes(method) || PRE_AUTH.some((p) => url.includes(p))) return config
  config.headers['x-csrf-token'] = await getCsrfToken()
  return config
})

// The token is bound to the session, so drop it whenever the session changes.
api.interceptors.response.use(
  (res) => {
    const url = res.config?.url || ''
    if (PRE_AUTH.some((p) => url.includes(p)) || url.includes('/auth/logout')) csrfToken = null
    return res
  },
  async (err) => {
    const cfg = err.config
    if (err.response?.status === 403 && /csrf/i.test(err.response?.data?.message || '') && cfg && !cfg._csrfRetried) {
      cfg._csrfRetried = true
      csrfToken = null
      return api(cfg)
    }
    throw err
  }
)