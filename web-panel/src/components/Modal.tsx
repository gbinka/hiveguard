import React from 'react'

interface Props {
  title: string
  open: boolean
  onClose: () => void
  children: React.ReactNode
  /** Extra classes on the modal panel */
  className?: string
}

export default function Modal({ title, open, onClose, children, className = '' }: Props) {
  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.6)' }}
      onClick={onClose}
    >
      <div
        className={`card w-full max-w-md shadow-2xl ${className}`}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-700/50 px-5 py-4">
          <h2 className="text-sm font-semibold text-gray-100">{title}</h2>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4">{children}</div>
      </div>
    </div>
  )
}
