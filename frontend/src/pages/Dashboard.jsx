import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import authService from '../services/authService'

function Dashboard() {
  const [user, setUser] = useState(null)
  const [showAddMoney, setShowAddMoney] = useState(false)
  const [showWithdraw, setShowWithdraw] = useState(false)
  const [amount, setAmount] = useState('')
  const [paymentMethod, setPaymentMethod] = useState('bkash')
  const [accountNumber, setAccountNumber] = useState('')
  const [message, setMessage] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    const userData = authService.getCurrentUser()
    if (!userData) navigate('/login')
    else setUser(userData)
  }, [navigate])

  const handleLogout = () => { authService.logout(); navigate('/login') }

  if (!user) return null

  return (
    <div className="min-h-screen bg-[#0a0a0a] bg-grid">
  {/* Navbar */}
  <nav className="glass-dark border-b border-cyan-500/30 sticky top-0 z-40">
    <div className="max-w-7xl mx-auto px-4 flex justify-between h-16 items-center">
      <h1 className="text-2xl font-bold font-orbitron text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400 neon-text cursor-pointer" onClick={() => navigate('/dashboard')}>
        TASK<span className="text-white">EARN</span>
      </h1>
      
      <div className="flex items-center gap-1">
        <button onClick={() => navigate('/dashboard')} className="text-cyan-400 hover:text-white px-4 py-2 rounded-lg text-sm font-orbitron tracking-wider transition-all hover:bg-cyan-500/20 border border-transparent hover:border-cyan-500/50">
          🏠 HOME
        </button>
        <button onClick={() => navigate('/tasks')} className="text-blue-400 hover:text-white px-4 py-2 rounded-lg text-sm font-orbitron tracking-wider transition-all hover:bg-blue-500/20 border border-transparent hover:border-blue-500/50">
          📋 TASKS
        </button>
        <button onClick={() => navigate('/packages')} className="text-green-400 hover:text-white px-4 py-2 rounded-lg text-sm font-orbitron tracking-wider transition-all hover:bg-green-500/20 border border-transparent hover:border-green-500/50">
          💎 PACKAGES
        </button>
        <button onClick={() => navigate('/profile')} className="text-purple-400 hover:text-white px-4 py-2 rounded-lg text-sm font-orbitron tracking-wider transition-all hover:bg-purple-500/20 border border-transparent hover:border-purple-500/50">
          👤 PROFILE
        </button>
        <button onClick={handleLogout} className="bg-red-500/20 border border-red-500/50 text-red-400 hover:text-white px-5 py-2 rounded-lg text-sm font-orbitron tracking-wider hover:bg-red-500/40 transition-all ml-2">
          ⏻ EXIT
        </button>
      </div>
    </div>
  </nav>

      <div className="max-w-7xl mx-auto py-8 px-4">
        <h2 className="text-3xl font-bold font-orbitron text-white mb-2">Welcome, <span className="text-cyan-400 neon-text">{user.fullName}</span></h2>
        <p className="text-gray-400 mb-8">Your earning dashboard</p>

        {message && (
          <div className="bg-cyan-500/20 border border-cyan-500/50 text-cyan-400 px-4 py-3 rounded-xl mb-6 flex justify-between items-center">
            <span>✅ {message}</span>
            <button onClick={() => setMessage('')} className="text-white font-bold">&times;</button>
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {[
            { label: 'Balance', value: `৳${user.balance || 0}`, color: 'cyan' },
            { label: 'Earnings', value: `৳${user.totalEarnings || 0}`, color: 'green' },
            { label: 'Tasks Done', value: user.completedTasks || 0, color: 'purple' }
          ].map((stat, i) => (
            <div key={i} className={`glass rounded-2xl p-6 border border-${stat.color}-500/30 neon-border text-${stat.color}-400 hover:scale-105 transition-transform`}>
              <p className="text-gray-400 text-sm font-orbitron tracking-wider">{stat.label}</p>
              <p className="text-4xl font-bold font-orbitron mt-2">{stat.value}</p>
            </div>
          ))}
        </div>

        {/* Action Buttons */}
        <div className="grid grid-cols-2 gap-4 mb-8">
          <button onClick={() => setShowAddMoney(true)} className="glass border border-cyan-500/50 text-cyan-400 py-5 rounded-2xl font-bold font-orbitron text-lg hover:shadow-[0_0_30px_rgba(0,255,255,0.3)] transition-all">💰 ADD FUNDS</button>
          <button onClick={() => setShowWithdraw(true)} className="glass border border-pink-500/50 text-pink-400 py-5 rounded-2xl font-bold font-orbitron text-lg hover:shadow-[0_0_30px_rgba(236,72,153,0.3)] transition-all">💸 WITHDRAW</button>
        </div>

        {/* Modals */}
        {showAddMoney && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="glass-dark rounded-3xl p-8 w-full max-w-md border border-cyan-500/30 neon-border text-cyan-400">
              <h3 className="text-2xl font-bold font-orbitron mb-6">ADD FUNDS</h3>
              <input type="number" value={amount} onChange={e => setAmount(e.target.value)} className="w-full bg-black/50 border border-cyan-500/50 rounded-xl px-4 py-3 text-white mb-4 focus:outline-none focus:border-cyan-400" placeholder="Amount (min ৳100)" />
              <select value={paymentMethod} onChange={e => setPaymentMethod(e.target.value)} className="w-full bg-black/50 border border-cyan-500/50 rounded-xl px-4 py-3 text-white mb-6 focus:outline-none">
                <option value="bkash">bKash</option>
                <option value="nagad">Nagad</option>
                <option value="rocket">Rocket</option>
              </select>
              <div className="flex gap-3">
                <button onClick={() => { setMessage(`Send ৳${amount} to our ${paymentMethod} number`); setShowAddMoney(false) }} className="flex-1 bg-cyan-500/20 border border-cyan-500 text-cyan-400 py-3 rounded-xl font-orbitron font-bold hover:bg-cyan-500/30">CONFIRM</button>
                <button onClick={() => setShowAddMoney(false)} className="flex-1 bg-gray-500/20 border border-gray-500 text-gray-400 py-3 rounded-xl font-orbitron">CANCEL</button>
              </div>
            </div>
          </div>
        )}

        {showWithdraw && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="glass-dark rounded-3xl p-8 w-full max-w-md border border-pink-500/30 neon-border text-pink-400">
              <h3 className="text-2xl font-bold font-orbitron mb-6">WITHDRAW</h3>
              <input type="number" value={amount} onChange={e => setAmount(e.target.value)} className="w-full bg-black/50 border border-pink-500/50 rounded-xl px-4 py-3 text-white mb-4 focus:outline-none" placeholder="Amount (min ৳100)" />
              <select value={paymentMethod} onChange={e => setPaymentMethod(e.target.value)} className="w-full bg-black/50 border border-pink-500/50 rounded-xl px-4 py-3 text-white mb-4 focus:outline-none">
                <option value="bkash">bKash</option>
                <option value="nagad">Nagad</option>
                <option value="rocket">Rocket</option>
              </select>
              <input type="text" value={accountNumber} onChange={e => setAccountNumber(e.target.value)} className="w-full bg-black/50 border border-pink-500/50 rounded-xl px-4 py-3 text-white mb-6 focus:outline-none" placeholder="Account number" />
              <div className="flex gap-3">
                <button onClick={() => { setMessage('Withdrawal request submitted!'); setShowWithdraw(false) }} className="flex-1 bg-pink-500/20 border border-pink-500 text-pink-400 py-3 rounded-xl font-orbitron font-bold hover:bg-pink-500/30">SUBMIT</button>
                <button onClick={() => setShowWithdraw(false)} className="flex-1 bg-gray-500/20 border border-gray-500 text-gray-400 py-3 rounded-xl font-orbitron">CANCEL</button>
              </div>
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="glass rounded-2xl p-6 border border-purple-500/20">
          <h3 className="text-xl font-bold font-orbitron text-purple-400 mb-4">QUICK ACTIONS</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'TASKS', path: '/tasks', color: 'blue' },
              { label: 'PACKAGES', path: '/packages', color: 'green' },
              { label: 'PROFILE', path: '/profile', color: 'purple' },
              { label: 'WITHDRAW', onClick: () => setShowWithdraw(true), color: 'pink' }
            ].map((btn, i) => (
              <button key={i} onClick={btn.onClick || (() => navigate(btn.path))} className={`glass border border-${btn.color}-500/30 text-${btn.color}-400 py-4 rounded-xl font-orbitron font-bold hover:shadow-[0_0_20px_rgba(168,85,247,0.3)] transition-all`}>
                {btn.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard