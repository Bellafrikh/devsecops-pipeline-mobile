import { useRef, useEffect } from 'react'

const levelClass = (line) => {
  if (line.includes('[ERROR]')) return 'log-error'
  if (line.includes('[WARN]')) return 'log-warn'
  return 'log-info'
}

export default function LogConsole({ logs = [], isLive = false }) {
  const bottomRef = useRef(null)
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  if (!logs.length) return (
    <div className="log-console" style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>
      Waiting for pipeline to start...
    </div>
  )

  return (
    <div className="log-console">
      {logs.map((line, i) => {
        const parts = line.match(/^\[(\d{2}:\d{2}:\d{2})\] \[(\w+)\] (.*)$/)
        if (parts) {
          return (
            <div key={i} className="log-line">
              <span className="log-ts">{parts[1]}</span>
              <span className={`log-${parts[2].toLowerCase()}`}>{parts[3]}</span>
            </div>
          )
        }
        return <div key={i} className={`log-line ${levelClass(line)}`}>{line}</div>
      })}
      {isLive && <div style={{ color: 'var(--accent)', fontSize: 12 }}>● Live</div>}
      <div ref={bottomRef} />
    </div>
  )
}
