import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { getRuns, getStats } from '../lib/api'
import { SeverityPie, FindingsBarChart } from '../components/SeverityChart'
import { Plus, GitBranch, Clock, CheckCircle, XCircle, AlertTriangle, Loader } from 'lucide-react'
import { createGlobalWs } from '../lib/api'

const GateBadge = ({ gate }) => {
  if (!gate) return <span className="badge badge-pending">—</span>
  const cls = { PASS: 'pass', FAIL: 'fail', WARN: 'warn' }[gate] || 'pending'
  return <span className={`badge badge-${cls}`}>{gate}</span>
}

const StatusIcon = ({ status }) => {
  const s = 14
  if (status === 'pass') return <CheckCircle size={s} color="var(--green)" />
  if (status === 'fail') return <XCircle size={s} color="var(--red)" />
  if (status === 'warn') return <AlertTriangle size={s} color="var(--yellow)" />
  if (status === 'running') return <Loader size={s} color="var(--blue)" className="spin" />
  return <Clock size={s} color="var(--text-muted)" />
}

export default function Dashboard() {
  const [runs, setRuns] = useState([])
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = async () => {
    try {
      const [runsRes, statsRes] = await Promise.all([getRuns({ limit: 20 }), getStats()])
      setRuns(runsRes.data)
      setStats(statsRes.data)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => {
    load()
    const ws = createGlobalWs()
    ws.onmessage = () => load()
    return () => ws.close()
  }, [])

  const latest = runs[0]
  const sev = latest
    ? { critical: latest.critical_count, high: latest.high_count, medium: latest.medium_count, low: latest.low_count }
    : {}

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', gap: 12, color: 'var(--text-muted)' }}>
      <Loader size={20} className="spin" /> Loading dashboard...
    </div>
  )

  return (
    <div>
      {/* KPI Cards */}
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
        <div className="stat-card accent">
          <div className="stat-value" style={{ color: 'var(--accent)' }}>{stats.total_runs || 0}</div>
          <div className="stat-label">Total Runs</div>
        </div>
        <div className="stat-card critical">
          <div className="stat-value" style={{ color: 'var(--critical)' }}>{stats.total_findings || 0}</div>
          <div className="stat-label">Total Findings</div>
        </div>
        <div className="stat-card high">
          <div className="stat-value" style={{ color: 'var(--high)' }}>{stats.total_tickets || 0}</div>
          <div className="stat-label">Open Tickets</div>
        </div>
        <div className="stat-card low">
          <div className="stat-value" style={{ color: 'var(--green)' }}>{stats.total_projects || 0}</div>
          <div className="stat-label">Projects</div>
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: 24 }}>
        {/* Latest scan chart */}
        <div className="card">
          <div className="card-title">Latest Scan — Severity Breakdown</div>
          {latest ? <SeverityPie data={sev} /> : <div className="empty-state"><p>No scans yet</p></div>}
        </div>
        {/* Trend */}
        <div className="card">
          <div className="card-title">Findings Trend (Last 10 Runs)</div>
          <FindingsBarChart runs={runs} />
        </div>
      </div>

      {/* Recent Runs Table */}
      <div className="card">
        <div className="flex justify-between items-center mb-4">
          <div className="card-title" style={{ marginBottom: 0 }}>Recent Runs</div>
          <button className="btn btn-primary btn-sm" onClick={() => navigate('/new-scan')}>
            <Plus size={14} /> New Scan
          </button>
        </div>
        {runs.length === 0 ? (
          <div className="empty-state">
            <GitBranch size={40} />
            <p>No pipeline runs yet. Start your first scan!</p>
            <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={() => navigate('/new-scan')}>
              <Plus size={14} /> New Scan
            </button>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr>
                <th>#</th><th>Repository</th><th>Branch</th><th>Status</th>
                <th>Gate</th><th>C</th><th>H</th><th>M</th><th>Score</th><th>Duration</th>
              </tr></thead>
              <tbody>
                {runs.map(r => (
                  <tr key={r.id} onClick={() => navigate(`/runs/${r.id}`)} style={{ cursor: 'pointer' }}>
                    <td><span className="font-mono text-muted">#{r.id}</span></td>
                    <td style={{ maxWidth: 200 }}>
                      <span style={{ fontSize: 13, fontWeight: 500 }} title={r.github_url}>
                        {r.github_url.replace('https://github.com/', '')}
                      </span>
                    </td>
                    <td><span className="badge badge-info">{r.branch}</span></td>
                    <td><div style={{ display: 'flex', alignItems: 'center', gap: 6 }}><StatusIcon status={r.status} />{r.status}</div></td>
                    <td><GateBadge gate={r.gate_result} /></td>
                    <td style={{ color: 'var(--critical)', fontWeight: 700 }}>{r.critical_count}</td>
                    <td style={{ color: 'var(--high)', fontWeight: 700 }}>{r.high_count}</td>
                    <td style={{ color: 'var(--medium)' }}>{r.medium_count}</td>
                    <td>{r.mobsf_score != null ? `${r.mobsf_score.toFixed(0)}/100` : '—'}</td>
                    <td className="text-muted">{r.duration_seconds ? `${r.duration_seconds.toFixed(0)}s` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
