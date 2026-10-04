import React, { createContext, useContext, useState } from 'react'

interface Toast {
  id: number
  type: 'success' | 'error' | 'info'
  message: string
}

interface ToastCtx {
  toasts: Toast[]
  success: (msg: string) => void
  error: (msg: string) => void
  info: (msg: string) => void
  dismiss: (id: number) => void
}

const ToastContext = createContext<ToastCtx>({
  toasts: [],
  success: () => {},
  error: () => {},
  info: () => {},
  dismiss: () => {},
})

let nextId = 1

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const add = (type: Toast['type'], message: string) => {
    const id = nextId++
    setToasts(p => [...p, { id, type, message }])
    setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), 4000)
  }

  const dismiss = (id: number) => setToasts(p => p.filter(t => t.id !== id))

  return (
    <ToastContext.Provider value={{ toasts, success: m => add('success', m), error: m => add('error', m), info: m => add('info', m), dismiss }}>
      {children}
      <ToastContainer />
    </ToastContext.Provider>
  )
}

export function useToast() {
  return useContext(ToastContext)
}

function ToastContainer() {
  const { toasts, dismiss } = useContext(ToastContext)

  if (toasts.length === 0) return null

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full">
      {toasts.map(t => (
        <div
          key={t.id}
          onClick={() => dismiss(t.id)}
          className={`flex items-start gap-3 rounded-lg px-4 py-3 shadow-xl cursor-pointer
            border backdrop-blur-sm text-sm font-medium transition-all
            ${t.type === 'success' ? 'bg-emerald-900/90 border-emerald-600/50 text-emerald-100' : ''}
            ${t.type === 'error'   ? 'bg-red-900/90 border-red-600/50 text-red-100' : ''}
            ${t.type === 'info'    ? 'bg-blue-900/90 border-blue-600/50 text-blue-100' : ''}
          `}
        >
          <span className="flex-1">{t.message}</span>
          <span className="opacity-60 text-xs mt-0.5">✕</span>
        </div>
      ))}
    </div>
  )
}
