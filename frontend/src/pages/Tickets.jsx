import { useState, useEffect } from 'react'
import { getTickets, updateTicket } from '../lib/api'
import { Filter, CheckCircle } from 'lucide-react'

const SevBadge = ({ s }) => <span className={`badge badge-${s}`}>{s}</span>

export default function Tickets() {
  const [tickets, setTickets] = useState([])
  const [filter, setFilter] = useState({ severity: '', status: '' })
  const [loading, setLoading] = useState(true)

  const load = async () => {
    const res = await getTickets({ severity: filter.severity || undefined, status: filter.status || undefined })
    setTickets(res.data); setLoading(false)
  }
  useEffect(() => { load() }, [filter])

  const resolve = async (id) => {
    await updateTicket(id, { status: 'resolved' }); load()
  }

  const grouped = tickets.reduce((acc, t) => {
    const k = t.severity; if (!acc[k]) acc[k] = []
    acc[k].push(t); return acc
  }, {})
  const order = ['critical', 'high', 'medium', 'low']

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 4 }}>Ticket Board</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>{tickets.length} tickets across all runs</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <select className="form-select" style={{ width: 'auto' }} value={filter.severity} onChange={e => setFilter(p => ({ ...p, severity: e.target.value }))}>
            <option value="">All Severities</option>
            {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>)}
          </select>
          <select className="form-select" style={{ width: 'auto' }} value={filter.status} onChange={e => setFilter(p => ({ ...p, status: e.target.value }))}>
            <option value="">All Status</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
      </div>

      {loading ? <div style={{ color: 'var(--text-muted)' }}>Loading tickets...</div>
        : tickets.length === 0 ? (
          <div className="empty-state">
            <CheckCircle size={48} />
            <p>No tickets found</p>
          </div>
        ) : (
          <div>
            {order.filter(s => grouped[s]).map(sev => (
              <div key={sev} style={{ marginBottom: 28 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                  <SevBadge s={sev} />
                  <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>{grouped[sev].length} ticket(s)</span>
                </div>
                {grouped[sev].map(t => (
                  <div key={t.id} className={`ticket-card ${t.severity}`}>
                    <div className="flex justify-between items-center mb-2">
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <SevBadge s={t.severity} />
                        <span className={`badge badge-${t.status === 'open' ? 'running' : t.status === 'resolved' ? 'pass' : 'warn'}`}>{t.status}</span>
                      </div>
                      {t.status === 'open' && (
                        <button className="btn btn-secondary btn-sm" onClick={() => resolve(t.id)}>
                          <CheckCircle size={12} /> Resolve
                        </button>
                      )}
                    </div>
                    <div className="ticket-title">{t.title}</div>
                    <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: '6px 0' }}>{t.description}</p>
                    {t.remediation && (
                      <div className="ticket-remediation">
                        <div className="ticket-remediation-title">💡 OWASP Recommendation</div>
                        {t.remediation}
                      </div>
                    )}
                    <div className="ticket-meta" style={{ marginTop: 8 }}>
                      <span>Run #{t.run_id}</span>
                      {t.cwe && <span>{t.cwe}</span>}
                      <span>{t.finding_count} finding(s)</span>
                      <span>{new Date(t.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            ))}
          </div>
        )
      }
    </div>
  )
}
