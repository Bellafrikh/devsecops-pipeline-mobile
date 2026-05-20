import { useState, useEffect, useRef } from 'react'
import { useParams } from 'react-router-dom'
import { getRun, getRunStages, getRunFindings, getRunTickets, getReleaseNotes, createWsConnection, cancelRun, relaunchRun } from '../lib/api'
import PipelineView from '../components/PipelineView'
import LogConsole from '../components/LogConsole'
import { SeverityPie } from '../components/SeverityChart'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { FileText, Bug, Ticket, BookOpen, RefreshCw, ExternalLink, Square, RotateCcw } from 'lucide-react'

const TABS = ['Pipeline', 'Findings', 'Tickets', 'Release Notes']

const SevBadge = ({ s }) => <span className={`badge badge-${s}`}>{s}</span>

export default function RunDetail() {
  const { id } = useParams()
  const [run, setRun] = useState(null)
  const [stages, setStages] = useState([])
  const [findings, setFindings] = useState([])
  const [tickets, setTickets] = useState([])
  const [notes, setNotes] = useState('')
  const [tab, setTab] = useState('Pipeline')
  const [selectedStage, setSelectedStage] = useState(null)
  const [logs, setLogs] = useState({}) // stageName → lines[]
  const [isLive, setIsLive] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [relaunching, setRelaunching] = useState(false)
  const wsRef = useRef(null)

  const isActive = (r) => r && (r.status === 'running' || r.status === 'pending')

  const handleCancel = async () => {
    if (!run || cancelling) return
    setCancelling(true)
    try { await cancelRun(run.id) } catch(e) { console.error(e) }
    setTimeout(() => { setCancelling(false); load() }, 2000)
  }

  const handleRelaunch = async () => {
    if (relaunching) return
    setRelaunching(true)
    try {
      const res = await relaunchRun(run.id)
      // Navigate to new run
      window.location.href = `/runs/${res.data.id}`
    } catch(e) {
      console.error(e)
      setRelaunching(false)
    }
  }

  const load = async () => {
    const [runRes, stagesRes] = await Promise.all([getRun(id), getRunStages(id)])
    setRun(runRes.data)
    setStages(stagesRes.data)
    // pre-load logs from DB
    const logMap = {}
    stagesRes.data.forEach(s => { if (s.logs) logMap[s.name] = s.logs.split('\n') })
    setLogs(logMap)
    if (!selectedStage && stagesRes.data.length) setSelectedStage(stagesRes.data[0].name)
  }

  const loadDetails = async () => {
    const [f, t, n] = await Promise.all([getRunFindings(id), getRunTickets(id), getReleaseNotes(id)])
    setFindings(f.data); setTickets(t.data); setNotes(n.data.content)
  }

  useEffect(() => {
    load(); loadDetails()
    // WebSocket for live updates
    const ws = createWsConnection(id)
    wsRef.current = ws
    ws.onopen = () => setIsLive(true)
    ws.onclose = () => setIsLive(false)
    ws.onmessage = (e) => {
      const ev = JSON.parse(e.data)
      if (ev.event === 'stage_log') {
        setLogs(prev => ({ ...prev, [ev.stage_name]: [...(prev[ev.stage_name] || []), ev.log_line] }))
      } else if (ev.event === 'stage_update') {
        setStages(prev => prev.map(s => s.name === ev.stage_name ? { ...s, status: ev.stage_status, ...ev.data } : s))
      } else if (ev.event === 'run_complete' || ev.event === 'run_cancelled' || ev.event === 'run_cancelling') {
        setIsLive(false); load(); loadDetails()
      }
    }
    return () => ws.close()
  }, [id])

  if (!run) return <div style={{ padding: 40, color: 'var(--text-muted)' }}>Loading run...</div>

  const currentLogs = logs[selectedStage] || []
  const gateColor = { PASS: 'var(--green)', FAIL: 'var(--red)', WARN: 'var(--yellow)' }[run.gate_result] || 'var(--text-muted)'

  return (
    <div>
      {/* Run header */}
      <div className="card mb-4">
        <div className="flex justify-between items-center mb-4">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700 }}>Run #{run.id}</h2>
              <span className={`badge badge-${run.status}`}>{run.status.toUpperCase()}</span>
              {run.gate_result && <span style={{ fontWeight: 700, color: gateColor, fontSize: 13 }}>Gate: {run.gate_result}</span>}
              {isLive && <span style={{ fontSize: 11, color: 'var(--blue)', background: 'var(--blue-dim)', padding: '2px 8px', borderRadius: 4 }} className="pulse">● LIVE</span>}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
              {run.github_url} @ {run.branch}
              {run.commit_sha && <span style={{ marginLeft: 8 }}>({run.commit_sha.slice(0, 8)})</span>}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button className="btn btn-secondary btn-sm" onClick={load} title="Refresh">
              <RefreshCw size={12} />
            </button>
            {isActive(run) && (
              <button
                className="btn btn-sm"
                onClick={handleCancel}
                disabled={cancelling}
                title="Stop Run"
                style={{ background: 'var(--red)', color: '#fff', opacity: cancelling ? 0.6 : 1 }}
              >
                <Square size={12} fill="currentColor" />
                {cancelling ? 'Stopping...' : 'Stop'}
              </button>
            )}
            {!isActive(run) && (
              <button
                className="btn btn-sm"
                onClick={handleRelaunch}
                disabled={relaunching}
                title="Relaunch with same parameters"
                style={{ background: 'var(--blue)', color: '#fff', opacity: relaunching ? 0.6 : 1 }}
              >
                <RotateCcw size={12} />
                {relaunching ? 'Launching...' : 'Relaunch'}
              </button>
            )}
            <a href={run.github_url} target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm">
              <ExternalLink size={12} /> Repo
            </a>
          </div>
        </div>
        {/* Quick stats */}
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          {[
            { label: 'Critical', val: run.critical_count, color: 'var(--critical)' },
            { label: 'High', val: run.high_count, color: 'var(--high)' },
            { label: 'Medium', val: run.medium_count, color: 'var(--medium)' },
            { label: 'Low', val: run.low_count, color: 'var(--low)' },
            { label: 'Secrets', val: run.secrets_count, color: 'var(--accent)' },
            { label: 'Score', val: run.mobsf_score != null ? `${run.mobsf_score.toFixed(0)}/100` : '—', color: 'var(--text-primary)' },
            { label: 'Duration', val: run.duration_seconds ? `${run.duration_seconds.toFixed(0)}s` : '…', color: 'var(--text-muted)' },
          ].map(({ label, val, color }) => (
            <div key={label} style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 22, fontWeight: 800, color }}>{val}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, borderBottom: '1px solid var(--border)', paddingBottom: 0 }}>
        {TABS.map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: '8px 16px', border: 'none', background: 'none', cursor: 'pointer',
            color: tab === t ? 'var(--accent)' : 'var(--text-muted)',
            borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
            fontFamily: 'var(--font)', fontWeight: 600, fontSize: 13, transition: 'all 0.15s',
          }}>{t}</button>
        ))}
      </div>

      {/* Tab: Pipeline */}
      {tab === 'Pipeline' && (
        <div>
          <PipelineView stages={stages} onSelectStage={setSelectedStage} selectedStage={selectedStage} />
          <div className="card">
            <div className="flex justify-between items-center mb-2">
              <div className="card-title" style={{ marginBottom: 0 }}>
                {selectedStage ? `Logs — ${selectedStage}` : 'Select a stage'}
              </div>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{currentLogs.length} lines</span>
            </div>
            <LogConsole logs={currentLogs} isLive={isLive && stages.find(s => s.name === selectedStage)?.status === 'running'} />
          </div>
        </div>
      )}

      {/* Tab: Findings */}
      {tab === 'Findings' && (
        <div>
          <div className="grid-2 mb-4">
            <div className="card">
              <div className="card-title">Severity Distribution</div>
              <SeverityPie data={{ critical: run.critical_count, high: run.high_count, medium: run.medium_count, low: run.low_count }} />
            </div>
            <div className="card">
              <div className="card-title">Source Breakdown</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, paddingTop: 8 }}>
                {['mobsf','sbom','secret_hunter','crypto_lint'].map(src => {
                  const count = findings.filter(f => f.source === src).length
                  return (
                    <div key={src} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 13, color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{src.replace('_',' ')}</span>
                      <span style={{ fontWeight: 700, color: count ? 'var(--text-primary)' : 'var(--text-muted)' }}>{count}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Severity</th><th>Source</th><th>Title</th><th>File</th><th>CWE</th></tr></thead>
              <tbody>
                {findings.map(f => (
                  <tr key={f.id}>
                    <td><SevBadge s={f.severity} /></td>
                    <td><span className="badge badge-info" style={{ fontSize: 10 }}>{f.source}</span></td>
                    <td style={{ maxWidth: 300, fontSize: 13 }} title={f.description}>{f.title}</td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-muted)', maxWidth: 200 }}>{f.file_path || '—'}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{f.cwe || '—'}</td>
                  </tr>
                ))}
                {!findings.length && <tr><td colSpan={5} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No findings</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab: Tickets */}
      {tab === 'Tickets' && (
        <div>
          {tickets.length === 0
            ? <div className="empty-state"><Ticket size={40} /><p>No tickets generated yet</p></div>
            : tickets.map(t => (
              <div key={t.id} className={`ticket-card ${t.severity}`}>
                <div className="flex justify-between items-center mb-2">
                  <span className={`badge badge-${t.severity}`}>{t.severity}</span>
                  <span className={`badge badge-${t.status === 'open' ? 'fail' : t.status === 'resolved' ? 'pass' : 'warn'}`}>{t.status}</span>
                </div>
                <div className="ticket-title">{t.title}</div>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: '8px 0' }}>{t.description}</p>
                {t.remediation && (
                  <div className="ticket-remediation">
                    <div className="ticket-remediation-title">💡 OWASP Recommendation</div>
                    {t.remediation}
                  </div>
                )}
                <div className="ticket-meta" style={{ marginTop: 8 }}>
                  {t.cwe && <span>CWE: {t.cwe}</span>}
                  <span>{t.finding_count} finding(s)</span>
                  {t.affected_files?.length > 0 && <span>Files: {t.affected_files.slice(0, 2).join(', ')}</span>}
                </div>
              </div>
            ))
          }
        </div>
      )}

      {/* Tab: Release Notes */}
      {tab === 'Release Notes' && (
        <div className="card">
          <div className="card-title"> Release Security Notes</div>
          {notes
            ? <div className="release-notes-content"><ReactMarkdown remarkPlugins={[remarkGfm]}>{notes}</ReactMarkdown></div>
            : <div className="empty-state"><BookOpen size={40} /><p>Release notes not yet generated</p></div>
          }
        </div>
      )}
    </div>
  )
}
