import { CheckCircle, XCircle, AlertTriangle, Clock, Loader, SkipForward, GitBranch, Shield, Key, Lock, Cpu, Cog, GitMerge, Bot } from 'lucide-react'

const STAGE_ICONS = {
  fetch_repo: GitBranch,
  sbom: Shield,
  secret_hunter: Key,
  crypto_lint: Lock,
  build_apk: Cog,
  mobsf: Cpu,
  policy_gate: GitMerge,
  ai_triage: Bot,
}

const STAGE_LABELS = {
  fetch_repo: 'Fetch Repo',
  sbom: 'SBOM + CVE',
  secret_hunter: 'SecretHunter',
  crypto_lint: 'CryptoLint',
  build_apk: 'Build APK',
  mobsf: 'MobSF SAST',
  policy_gate: 'Policy Gate',
  ai_triage: 'AI Triage',
}

// Stages that run in parallel (for visual grouping)
const PARALLEL_STAGES = new Set(['sbom', 'secret_hunter', 'crypto_lint'])

const StatusIcon = ({ status }) => {
  const s = { width: 18, height: 18 }
  if (status === 'pass') return <CheckCircle {...s} color="var(--green)" />
  if (status === 'fail') return <XCircle {...s} color="var(--red)" />
  if (status === 'warn') return <AlertTriangle {...s} color="var(--yellow)" />
  if (status === 'running') return <Loader {...s} color="var(--blue)" className="spin" />
  if (status === 'skipped') return <SkipForward {...s} color="var(--text-muted)" />
  return <Clock {...s} color="var(--text-muted)" />
}

export default function PipelineView({ stages = [], onSelectStage, selectedStage }) {
  const ordered = ['fetch_repo', 'sbom', 'secret_hunter', 'crypto_lint', 'build_apk', 'mobsf', 'policy_gate', 'ai_triage']
  const stageMap = Object.fromEntries(stages.map(s => [s.name, s]))

  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontFamily: 'var(--mono)' }}>
        SBOM + SecretHunter + CryptoLint run in <span style={{ color: 'var(--blue)' }}>parallel</span> (Fail-Fast)
      </div>
      <div className="pipeline-stages">
        {ordered.map((name) => {
          const stage = stageMap[name]
          const status = stage?.status || 'pending'
          const isSelected = selectedStage === name
          const isParallel = PARALLEL_STAGES.has(name)
          const IconComp = STAGE_ICONS[name]
          return (
            <div
              key={name}
              className={`stage-step ${status}`}
              onClick={() => onSelectStage?.(name)}
              style={{
                cursor: 'pointer',
                outline: isSelected ? '2px solid var(--accent)' : 'none',
                outlineOffset: '-2px',
                borderTop: isParallel ? '2px solid var(--blue-dim)' : undefined,
              }}
            >
              <div className="stage-icon">
                {IconComp && <IconComp size={20} strokeWidth={1.5} />}
              </div>
              <div className="stage-name">{STAGE_LABELS[name]}</div>
              <div style={{ marginTop: 6 }}><StatusIcon status={status} /></div>
              {stage?.duration_seconds && (
                <div className="stage-duration">{stage.duration_seconds.toFixed(1)}s</div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
