interface Props {
  className?: string
}

/** ArgusBot mark: lucide-style robot head with a single Argus eye (almond + iris)
    instead of two eyes. Stroke follows currentColor like lucide icons. */
export default function SauronBotIcon({ className }: Props) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {/* antenna */}
      <line x1="12" y1="4" x2="12" y2="6.5" />
      <circle cx="12" cy="3.2" r="0.9" fill="currentColor" stroke="none" />
      {/* robot head */}
      <rect x="4" y="6.5" width="16" height="12.5" rx="3.5" />
      {/* ears */}
      <line x1="4" y1="12.5" x2="2.3" y2="12.5" />
      <line x1="21.7" y1="12.5" x2="20" y2="12.5" />
      {/* single Argus eye (almond) with iris */}
      <path d="M7.2 12.7 Q12 9.4 16.8 12.7 Q12 16 7.2 12.7 Z" fill="currentColor" fillOpacity="0.14" />
      <circle cx="12" cy="12.7" r="1.5" fill="currentColor" stroke="none" />
    </svg>
  )
}
