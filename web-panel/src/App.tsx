import { useEffect, useState } from 'react'
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { probe } from './api/client'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Bans from './pages/Bans'
import Bots from './pages/Bots'
import Whitelist from './pages/Whitelist'
import Cluster from './pages/Cluster'
import Config from './pages/Config'
import Rules from './pages/Rules'
import Fail2ban from './pages/Fail2ban'
import { ApiUnauthorizedError } from './api/client'

type AuthState = 'loading' | 'ok' | 'needs-login'

function Spinner() {
  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: '#181b24' }}>
      <div className="flex flex-col items-center gap-4">
        <span className="text-4xl animate-pulse">🐝</span>
        <p className="text-sm text-gray-500">Connecting to HiveGuard…</p>
      </div>
    </div>
  )
}

function RequireAuth({ children, authState }: { children: JSX.Element; authState: AuthState }) {
  if (authState === 'loading') return <Spinner />
  if (authState === 'needs-login') return <Navigate to="/login" replace />
  return children
}

export default function App() {
  const [authState, setAuthState] = useState<AuthState>('loading')
  const navigate = useNavigate()

  useEffect(() => {
    probe().then(({ ok, needsAuth }) => {
      if (ok) {
        setAuthState('ok')
      } else if (needsAuth) {
        setAuthState('needs-login')
      } else {
        // Server unreachable or no token stored → try anyway; errors surface per-request
        setAuthState('ok')
      }
    })
  }, [])

  // Listen for 401 errors bubbled up from React Query and redirect to login
  useEffect(() => {
    const handler = (e: ErrorEvent) => {
      if (e.error instanceof ApiUnauthorizedError) {
        setAuthState('needs-login')
        navigate('/login', { replace: true })
      }
    }
    window.addEventListener('error', handler)
    return () => window.removeEventListener('error', handler)
  }, [navigate])

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <RequireAuth authState={authState}>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="bans" element={<Bans />} />
        <Route path="bots" element={<Bots />} />
        <Route path="whitelist" element={<Whitelist />} />
        <Route path="cluster" element={<Cluster />} />
        <Route path="rules" element={<Rules />} />
        <Route path="config" element={<Config />} />
        <Route path="fail2ban" element={<Fail2ban />} />
      </Route>
      {/* Catch-all: redirect to root */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
