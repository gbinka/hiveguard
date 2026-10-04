import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  ShieldOff,
  Bot,
  ShieldCheck,
  Network,
  LogOut,
  Menu,
  X,
  Wifi,
  WifiOff,
  Settings,
  SlidersHorizontal,
  ArrowDownToLine,
} from 'lucide-react'
import { clearToken } from '../api/client'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'

const NAV = [
  { to: '/',          label: 'Dashboard', icon: <LayoutDashboard size={18} />, exact: true },
  { to: '/bans',      label: 'Bans',      icon: <ShieldOff size={18} /> },
  { to: '/bots',      label: 'Bots',      icon: <Bot size={18} /> },
  { to: '/whitelist', label: 'Whitelist', icon: <ShieldCheck size={18} /> },
  { to: '/cluster',   label: 'Cluster',   icon: <Network size={18} /> },
]

const NAV_ADMIN = [
  { to: '/rules',     label: 'Rules',     icon: <SlidersHorizontal size={18} /> },
  { to: '/config',    label: 'Config',    icon: <Settings size={18} /> },
  { to: '/fail2ban',  label: 'Fail2ban',  icon: <ArrowDownToLine size={18} /> },
]

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false)
  const navigate = useNavigate()

  // Lightweight heartbeat to show connection state
  const { isError } = useQuery({
    queryKey: ['heartbeat'],
    queryFn: api.getStats,
    refetchInterval: 15_000,
    retry: false,
  })

  const handleLogout = () => {
    clearToken()
    navigate('/login')
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#181b24' }}>
      {/* Sidebar */}
      <aside
        className={`flex flex-col shrink-0 border-r border-gray-700/50 bg-gray-900/70
          backdrop-blur-sm transition-all duration-200 ${collapsed ? 'w-14' : 'w-52'}`}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-3 py-4 border-b border-gray-700/40">
          <span className="text-2xl shrink-0">🐝</span>
          {!collapsed && (
            <span className="font-bold text-gray-100 text-sm tracking-wide truncate">
              HiveGuard
            </span>
          )}
          <button
            onClick={() => setCollapsed(c => !c)}
            className="ml-auto text-gray-500 hover:text-gray-300 transition-colors"
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <Menu size={16} /> : <X size={16} />}
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-3 px-1.5 space-y-0.5">
          {NAV.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.exact}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-md px-2.5 py-2 text-sm font-medium
                 transition-colors
                 ${isActive
                   ? 'bg-blue-600/20 text-blue-300 ring-1 ring-blue-500/30'
                   : 'text-gray-400 hover:bg-gray-700/50 hover:text-gray-200'}`
              }
              title={collapsed ? item.label : undefined}
            >
              <span className="shrink-0">{item.icon}</span>
              {!collapsed && <span className="truncate">{item.label}</span>}
            </NavLink>
          ))}

          {/* Admin section divider */}
          {!collapsed && (
            <div className="pt-3 pb-1 px-2.5">
              <span className="text-[10px] font-semibold uppercase tracking-widest text-gray-600">
                Admin
              </span>
            </div>
          )}
          {collapsed && <div className="my-2 border-t border-gray-700/40" />}

          {NAV_ADMIN.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-md px-2.5 py-2 text-sm font-medium
                 transition-colors
                 ${isActive
                   ? 'bg-blue-600/20 text-blue-300 ring-1 ring-blue-500/30'
                   : 'text-gray-400 hover:bg-gray-700/50 hover:text-gray-200'}`
              }
              title={collapsed ? item.label : undefined}
            >
              <span className="shrink-0">{item.icon}</span>
              {!collapsed && <span className="truncate">{item.label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* Bottom: connection status + logout */}
        <div className="border-t border-gray-700/40 px-1.5 py-3 space-y-0.5">
          {/* Connection indicator */}
          <div
            className={`flex items-center gap-3 rounded-md px-2.5 py-2 text-xs
              ${isError ? 'text-red-400' : 'text-emerald-400'}`}
            title={isError ? 'Server unreachable' : 'Connected'}
          >
            <span className="shrink-0">
              {isError ? <WifiOff size={16} /> : <Wifi size={16} />}
            </span>
            {!collapsed && (
              <span className="truncate font-medium">
                {isError ? 'Disconnected' : 'Connected'}
              </span>
            )}
          </div>

          {/* Logout */}
          <button
            onClick={handleLogout}
            className="flex w-full items-center gap-3 rounded-md px-2.5 py-2 text-sm
                       font-medium text-gray-400 hover:bg-gray-700/50 hover:text-gray-200
                       transition-colors"
            title={collapsed ? 'Logout' : undefined}
          >
            <span className="shrink-0"><LogOut size={18} /></span>
            {!collapsed && <span>Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  )
}
