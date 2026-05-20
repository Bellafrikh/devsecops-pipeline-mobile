import { RadialBarChart, RadialBar, PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts'

const SEV_COLORS = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e', info: '#6366f1'
}

export function SeverityPie({ data }) {
  const chartData = Object.entries(data)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, value: v, color: SEV_COLORS[k] }))

  if (!chartData.length) return (
    <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No findings</div>
  )
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={chartData} cx="50%" cy="50%" innerRadius={55} outerRadius={90} dataKey="value" paddingAngle={2}>
          {chartData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
        </Pie>
        <Tooltip
          contentStyle={{ background: '#161b2e', border: '1px solid #252d47', borderRadius: 8, color: '#e2e8f0' }}
          formatter={(v, n) => [v, n.charAt(0).toUpperCase() + n.slice(1)]}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

export function FindingsBarChart({ runs = [] }) {
  const data = runs.slice(0, 10).reverse().map((r, i) => ({
    name: `#${r.id}`,
    critical: r.critical_count,
    high: r.high_count,
    medium: r.medium_count,
    low: r.low_count,
  }))
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} barSize={12}>
        <CartesianGrid strokeDasharray="3 3" stroke="#252d47" />
        <XAxis dataKey="name" tick={{ fill: '#4a5568', fontSize: 11 }} />
        <YAxis tick={{ fill: '#4a5568', fontSize: 11 }} />
        <Tooltip contentStyle={{ background: '#161b2e', border: '1px solid #252d47', borderRadius: 8, color: '#e2e8f0' }} />
        <Bar dataKey="critical" fill="#ef4444" stackId="a" />
        <Bar dataKey="high" fill="#f97316" stackId="a" />
        <Bar dataKey="medium" fill="#f59e0b" stackId="a" />
        <Bar dataKey="low" fill="#22c55e" stackId="a" radius={[4,4,0,0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}
