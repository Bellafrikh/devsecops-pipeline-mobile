import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Play, Ticket, Shield, Settings, Zap, GitBranch
} from 'lucide-react'

const links = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/runs', icon: GitBranch, label: 'Pipeline Runs' },
  { to: '/new-scan', icon: Play, label: 'New Scan' },
  { to: '/tickets', icon: Ticket, label: 'Tickets' },
  { to: '/policy', icon: Shield, label: 'Policy-as-Code' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <h1>SecurePipeline</h1>
        <span>Mobile DevSecOps Platform</span>
      </div>
      <nav className="sidebar-nav">
        {links.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to} to={to}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            <Icon size={18} />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)', fontSize: 12 }}>
          <Zap size={14} />
          Pipeline Engine v1.0
        </div>
      </div>
    </aside>
  )
}
