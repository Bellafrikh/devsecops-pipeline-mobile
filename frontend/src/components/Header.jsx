import { useLocation } from 'react-router-dom'
import { Bell, Activity } from 'lucide-react'

const pageTitles = {
  '/dashboard': 'Dashboard',
  '/new-scan': 'New Scan',
  '/tickets': 'Ticket Board',
  '/policy': 'Policy-as-Code',
  '/settings': 'Settings',
}

export default function Header() {
  const { pathname } = useLocation()
  const title = pageTitles[pathname] || 'Run Detail'
  return (
    <header className="header">
      <span className="header-title">{title}</span>
      <div className="header-actions">
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--green)', background: 'var(--green-dim)', padding: '4px 10px', borderRadius: 6 }}>
          <Activity size={12} className="pulse" /> Engine Online
        </div>
      </div>
    </header>
  )
}
