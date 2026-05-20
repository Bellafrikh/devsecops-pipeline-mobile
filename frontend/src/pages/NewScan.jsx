import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { createRun, getPolicies } from '../lib/api'
import { Play, GitBranch, Shield, AlertTriangle, Info } from 'lucide-react'

const DEMO_REPOS = [
  { label: 'OWASP InsecureBankv2 (demo APK)', url: 'https://github.com/dineshshetty/Android-InsecureBankv2', branch: 'master' },
  { label: 'OWASP MSTG UnCrackable L1', url: 'https://github.com/OWASP/owasp-mstg', branch: 'master' },
  { label: 'Damn Insecure Vulnerable Android App', url: 'https://github.com/payatu/diva-android', branch: 'master' },
]

export default function NewScan() {
  const [form, setForm] = useState({ github_url: '', branch: 'main', policy_id: '' })
  const [policies, setPolicies] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    getPolicies().then(r => setPolicies(r.data)).catch(() => {})
  }, [])

  const set = (k, v) => setForm(p => ({ ...p, [k]: v }))

  const handleDemo = (demo) => setForm(p => ({ ...p, github_url: demo.url, branch: demo.branch }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.github_url.trim()) return setError('GitHub URL is required')
    setLoading(true); setError('')
    try {
      const res = await createRun({
        github_url: form.github_url.trim(),
        branch: form.branch || 'main',
        policy_id: form.policy_id ? parseInt(form.policy_id) : undefined,
      })
      navigate(`/runs/${res.data.id}`)
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to start scan')
    } finally { setLoading(false) }
  }

  return (
    <div style={{ maxWidth: 720, margin: '0 auto' }}>
      <div style={{ marginBottom: 28 }}>
        <h2 style={{ fontSize: 22, fontWeight: 700, marginBottom: 6 }}> Launch Security Scan</h2>
        <p style={{ color: 'var(--text-secondary)' }}>
          Paste any Android GitHub repository URL. The pipeline will clone, build, and run all 7 security stages.
        </p>
      </div>

      {/* Demo repos */}
      <div className="card mb-6">
        <div className="card-title"> Quick Demo</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {DEMO_REPOS.map(d => (
            <button key={d.url} className="btn btn-secondary" style={{ justifyContent: 'flex-start', textAlign: 'left' }}
              onClick={() => handleDemo(d)}>
              <GitBranch size={14} />
              <span style={{ flex: 1, fontWeight: 500 }}>{d.label}</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{d.url.replace('https://github.com/', '')}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Scan form */}
      <form onSubmit={handleSubmit}>
        <div className="card">
          <div className="card-title">Pipeline Configuration</div>

          <div className="form-group">
            <label className="form-label"><GitBranch size={12} style={{ display: 'inline', marginRight: 4 }} />GitHub Repository URL *</label>
            <input
              className="form-input"
              placeholder="https://github.com/user/android-app"
              value={form.github_url}
              onChange={e => set('github_url', e.target.value)}
              required
            />
          </div>

          <div className="grid-2">
            <div className="form-group">
              <label className="form-label"><GitBranch size={12} style={{ display: 'inline', marginRight: 4 }} />Branch</label>
              <input className="form-input" placeholder="main" value={form.branch}
                onChange={e => set('branch', e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label"><Shield size={12} style={{ display: 'inline', marginRight: 4 }} />Security Policy</label>
              <select className="form-select" value={form.policy_id} onChange={e => set('policy_id', e.target.value)}>
                <option value="">Default Policy</option>
                {policies.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
          </div>

          {/* Stage preview */}
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Pipeline Stages
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {['📦 Fetch & Build','🔍 MobSF SAST',' SBOM + CVE','🔑 SecretHunter','🔐 CryptoLint','🚦 Policy Gate','🤖 AI Triage'].map(s => (
                <span key={s} style={{ padding: '4px 10px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }}>{s}</span>
              ))}
            </div>
          </div>

          <div style={{ background: 'var(--blue-dim)', border: '1px solid var(--blue)30', borderRadius: 8, padding: 12, display: 'flex', gap: 8, marginBottom: 20, fontSize: 13 }}>
            <Info size={14} color="var(--blue)" style={{ flexShrink: 0, marginTop: 1 }} />
            <span style={{ color: 'var(--text-secondary)' }}>
              Results stream in real-time. You'll be redirected to the live run view once the pipeline starts.
            </span>
          </div>

          {error && (
            <div style={{ background: 'var(--red-dim)', border: '1px solid var(--red)30', borderRadius: 8, padding: 12, display: 'flex', gap: 8, marginBottom: 16, color: 'var(--red)', fontSize: 13 }}>
              <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 1 }} /> {error}
            </div>
          )}

          <button className="btn btn-primary w-full" type="submit" disabled={loading} style={{ padding: '12px 24px', fontSize: 15 }}>
            {loading ? <><span className="spin" style={{ display: 'inline-block' }}>⏳</span> Launching Pipeline...</>
              : <><Play size={16} /> Launch Security Pipeline</>}
          </button>
        </div>
      </form>
    </div>
  )
}
