import { Server, Bot, Key } from 'lucide-react'

export default function Settings() {
  return (
    <div style={{ maxWidth: 720 }}>
      <div style={{ marginBottom: 28 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 4 }}>Settings</h2>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>Configure your platform integrations and AI provider.</p>
      </div>

      <div className="card mb-4">
        <div className="card-title"><Server size={13} style={{ display: 'inline', marginRight: 6 }} />MobSF Connection</div>
        <div className="form-group">
          <label className="form-label">MobSF URL</label>
          <input className="form-input" defaultValue="http://mobsf:8000" />
        </div>
        <div className="form-group">
          <label className="form-label">API Key</label>
          <input className="form-input" type="password" placeholder="Set in .env: MOBSF_API_KEY" />
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: -8, marginBottom: 16 }}>
          Configure via <code style={{ background: 'var(--bg-hover)', padding: '1px 5px', borderRadius: 3 }}>.env</code> file. MobSF runs automatically via Docker Compose.
        </div>
        <button className="btn btn-secondary btn-sm">Test Connection</button>
      </div>

      <div className="card mb-4">
        <div className="card-title"><Bot size={13} style={{ display: 'inline', marginRight: 6 }} />AI Triage Provider</div>
        <div className="form-group">
          <label className="form-label">Provider</label>
          <select className="form-select">
            <option value="ollama">Ollama (Local — Free, Private)</option>
            <option value="openai">OpenAI (Cloud — Requires API Key)</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Ollama Model</label>
          <input className="form-input" defaultValue="llama3" />
        </div>
        <div className="form-group">
          <label className="form-label">OpenAI API Key (optional)</label>
          <input className="form-input" type="password" placeholder="sk-..." />
        </div>
        <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>Changes take effect on next pipeline run. Set values in <code style={{ background: 'var(--bg-hover)', padding: '1px 5px', borderRadius: 3 }}>.env</code> for persistence.</p>
      </div>

      <div className="card">
        <div className="card-title"><Key size={13} style={{ display: 'inline', marginRight: 6 }} />Pipeline Limits</div>
        <div className="grid-2">
          <div className="form-group">
            <label className="form-label">Max Concurrent Runs</label>
            <input className="form-input" type="number" defaultValue={3} min={1} max={10} />
          </div>
          <div className="form-group">
            <label className="form-label">Build Timeout (seconds)</label>
            <input className="form-input" type="number" defaultValue={600} />
          </div>
        </div>
        <div style={{ background: 'var(--yellow-dim)', border: '1px solid var(--yellow)30', borderRadius: 8, padding: 12, fontSize: 12, color: 'var(--text-secondary)' }}>
           Settings UI is read-only in this version. Edit <code>.env</code> and restart the backend to apply changes.
        </div>
      </div>
    </div>
  )
}
