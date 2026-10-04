import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { KeyRound, Loader2, AlertCircle } from 'lucide-react'
import { setToken, getToken } from '../api/client'

export default function Login() {
  const [token, setTokenInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError('')

    // Temporarily store the token so `client.ts` picks it up
    const prev = getToken()
    setToken(token.trim())

    try {
      const headers: HeadersInit = {}
      const t = token.trim()
      if (t) headers['Authorization'] = `Bearer ${t}`

      const resp = await fetch('/api/stats', { headers })

      if (resp.ok) {
        window.location.replace('/')
      } else if (resp.status === 401) {
        setToken(prev) // restore
        setError('Invalid token. Check your hiveguard config → api.auth_token.')
      } else {
        setError(`Server returned ${resp.status}. Is HiveGuard running?`)
        setToken(prev)
      }
    } catch {
      setError('Cannot reach server. Make sure you are connected via SSH tunnel.')
      setToken(prev)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{ background: 'radial-gradient(ellipse at 50% 0%, #1e2a44 0%, #181b24 60%)' }}
    >
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="text-5xl mb-3">🐝</div>
          <h1 className="text-2xl font-bold text-gray-100">HiveGuard</h1>
          <p className="text-sm text-gray-400 mt-1">Web Panel</p>
        </div>

        {/* Card */}
        <div className="card p-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="token"
                className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wider"
              >
                API Token
              </label>
              <div className="relative">
                <KeyRound
                  size={15}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
                />
                <input
                  id="token"
                  type="password"
                  autoComplete="current-password"
                  value={token}
                  onChange={e => setTokenInput(e.target.value)}
                  placeholder="Leave blank if auth is disabled"
                  className="input pl-9"
                />
              </div>
              <p className="mt-1.5 text-xs text-gray-600">
                Set in <code className="font-mono text-gray-500">config.yaml → api.auth_token</code>
              </p>
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-md bg-red-900/30 border border-red-700/40 px-3 py-2 text-sm text-red-300">
                <AlertCircle size={15} className="shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full justify-center py-2"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : null}
              {loading ? 'Connecting…' : 'Connect'}
            </button>
          </form>
        </div>

        <p className="mt-4 text-center text-xs text-gray-600">
          Recommended usage via SSH tunnel:{' '}
          <code className="font-mono text-gray-500">ssh -L 8443:127.0.0.1:8443 user@server</code>
        </p>
      </div>
    </div>
  )
}
