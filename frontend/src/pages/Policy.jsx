import { useState, useEffect } from 'react'
import { getPolicies, createPolicy, updatePolicy, deletePolicy } from '../lib/api'
import Editor from '@monaco-editor/react'
import { Plus, Save, Trash2, Shield, ChevronRight } from 'lucide-react'
import yaml from 'js-yaml'

const DEFAULT_YAML = `version: "1.0"
name: "My Custom Policy"
description: "Customize thresholds for your project"

thresholds:
  critical: 0
  high: 5
  medium: 20
  low: 50

scanners:
  mobsf:
    enabled: true
    fail_on_score_below: 40
  sbom:
    enabled: true
    fail_on_critical_cve: true
  secret_hunter:
    enabled: true
    block_on_any_secret: true
    entropy_threshold: 4.5
  crypto_lint:
    enabled: true
    severity: warn

ai_triage:
  enabled: true
  ticket_auto_create: true
  release_notes: true
`

export default function Policy() {
  const [policies, setPolicies] = useState([])
  const [selected, setSelected] = useState(null)
  const [yamlContent, setYamlContent] = useState(DEFAULT_YAML)
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  const load = async () => {
    const res = await getPolicies(); setPolicies(res.data)
    if (!selected && res.data.length) { setSelected(res.data[0]); setYamlContent(res.data[0].yaml_content); setName(res.data[0].name) }
  }
  useEffect(() => { load() }, [])

  const handleSelect = (p) => { setSelected(p); setYamlContent(p.yaml_content); setName(p.name); setError(''); setSaved(false) }

  const handleNew = () => { setSelected(null); setYamlContent(DEFAULT_YAML); setName('New Policy'); setError('') }

  const handleSave = async () => {
    setError('')
    try { yaml.load(yamlContent) } catch (e) { return setError(`YAML Error: ${e.message}`) }
    try {
      if (selected) {
        await updatePolicy(selected.id, { name, yaml_content: yamlContent })
      } else {
        await createPolicy({ name, yaml_content: yamlContent })
      }
      setSaved(true); setTimeout(() => setSaved(false), 2000); load()
    } catch (e) { setError(e.response?.data?.detail || 'Save failed') }
  }

  const handleDelete = async () => {
    if (!selected || selected.is_default) return
    if (!confirm(`Delete policy "${selected.name}"?`)) return
    await deletePolicy(selected.id); setSelected(null); setYamlContent(DEFAULT_YAML); setName(''); load()
  }

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 4 }}>🛡️ Policy-as-Code</h2>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>Define security thresholds, scanner configs, and AI triage rules per project. Policies are versioned YAML.</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', gap: 20 }}>
        {/* Policy List */}
        <div>
          <div className="card" style={{ padding: 12 }}>
            <button className="btn btn-primary btn-sm w-full mb-2" onClick={handleNew}><Plus size={13} /> New Policy</button>
            {policies.map(p => (
              <div key={p.id} onClick={() => handleSelect(p)} style={{
                padding: '10px 12px', borderRadius: 8, cursor: 'pointer', marginBottom: 4,
                background: selected?.id === p.id ? 'var(--accent-glow)' : 'transparent',
                border: `1px solid ${selected?.id === p.id ? 'var(--accent)' : 'transparent'}`,
                transition: 'all 0.15s',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Shield size={13} color={selected?.id === p.id ? 'var(--accent)' : 'var(--text-muted)'} />
                  <span style={{ fontSize: 13, fontWeight: 500, color: selected?.id === p.id ? 'var(--accent-hover)' : 'var(--text-primary)' }}>{p.name}</span>
                </div>
                {p.is_default && <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 21 }}>default</span>}
              </div>
            ))}
          </div>
        </div>

        {/* Editor */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 12, alignItems: 'center' }}>
            <input className="form-input" style={{ flex: 1 }} placeholder="Policy name" value={name} onChange={e => setName(e.target.value)} />
            <button className="btn btn-primary btn-sm" onClick={handleSave}><Save size={13} /> {saved ? 'Saved!' : 'Save'}</button>
            {selected && !selected.is_default && (
              <button className="btn btn-danger btn-sm" onClick={handleDelete}><Trash2 size={13} /></button>
            )}
          </div>
          {error && <div style={{ background: 'var(--red-dim)', padding: '8px 20px', fontSize: 12, color: 'var(--red)' }}>{error}</div>}
          <Editor
            height="600px"
            language="yaml"
            value={yamlContent}
            onChange={v => setYamlContent(v || '')}
            theme="vs-dark"
            options={{
              fontSize: 13, fontFamily: 'JetBrains Mono, monospace',
              minimap: { enabled: false }, scrollBeyondLastLine: false,
              lineNumbers: 'on', wordWrap: 'on', padding: { top: 16 },
            }}
          />
        </div>
      </div>
    </div>
  )
}
