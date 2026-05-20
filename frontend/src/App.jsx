import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import Runs from './pages/Runs'
import RunDetail from './pages/RunDetail'
import Tickets from './pages/Tickets'
import Policy from './pages/Policy'
import Settings from './pages/Settings'

export default function App() {
  return (
    <BrowserRouter>
      <div className="layout">
        <Sidebar />
        <div className="main-content">
          <Header />
          <main className="page fade-in">
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/new-scan" element={<NewScan />} />
              <Route path="/runs" element={<Runs />} />
              <Route path="/runs/:id" element={<RunDetail />} />
              <Route path="/tickets" element={<Tickets />} />
              <Route path="/policy" element={<Policy />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  )
}
