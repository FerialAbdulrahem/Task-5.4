import axios from 'axios'

// withCredentials sends the httpOnly auth cookie. Because the browser also sends it
// on cross-site requests, every state-changing request additionally carries a CSRF
// token header that a foreign site cannot read or forge.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null

export async function fetchCsrfToken() {
  const { data } = await api.get('/csrf-token')
  csrfToken = data.csrfToken
  return csrfToken
}

const SAFE_METHODS = ['get', 'head', 'options']
const isPreAuth = (url = '') => /\/auth\/(login|register)$/.test(url)
const isAuthChange = (url = '') => /\/auth\/(login|register|logout)$/.test(url)

// Attach the token to every mutating request (login/register are exempt: no session yet)
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!SAFE_METHODS.includes(method) && !isPreAuth(config.url)) {
    if (!csrfToken) await fetchCsrfToken()
    config.headers['x-csrf-token'] = csrfToken
  }
  return config
})

// The token is bound to the session cookie. After login/register/logout the session
// changes, so drop the cached token; the next write fetches a fresh one.
api.interceptors.response.use((res) => {
  if (isAuthChange(res.config?.url)) csrfToken = null
  return res
})