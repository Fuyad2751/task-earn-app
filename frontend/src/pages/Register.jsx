import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import authService from '../services/authService'

function Register() {
  const [formData, setFormData] = useState({
    fullName: '', email: '', phone: '', password: '', confirmPassword: '', referralCode: ''
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match')
      return
    }
    setLoading(true)
    try {
      await authService.register({
        fullName: formData.fullName,
        email: formData.email,
        phone: formData.phone,
        password: formData.password,
        referralCode: formData.referralCode
      })
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#0a0a0a] bg-grid flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-purple-500 rounded-full blur-[128px] opacity-20 animate-pulse"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-pink-500 rounded-full blur-[128px] opacity-20 animate-pulse delay-1000"></div>

      <div className="glass-dark rounded-3xl w-full max-w-md p-8 relative z-10 border border-purple-500/30 max-h-[90vh] overflow-y-auto neon-border text-purple-400">
        <div className="text-center mb-6">
          <h1 className="text-4xl font-bold font-orbitron text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-cyan-400 neon-text">
            JOIN <span className="text-white">US</span>
          </h1>
          <p className="text-gray-400 mt-2">Start earning today</p>
        </div>

        {error && (
          <div className="bg-red-500/20 border border-red-500 text-red-400 px-4 py-3 rounded-xl mb-4 text-sm flex items-center gap-2">
            <span>⚠️</span> {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-purple-400 text-sm font-medium mb-1 font-orbitron tracking-wider text-xs">FULL NAME</label>
            <input type="text" name="fullName" value={formData.fullName} onChange={(e) => setFormData({...formData, fullName: e.target.value})} className="w-full bg-black/50 border border-purple-500/50 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-purple-400 focus:shadow-[0_0_20px_rgba(168,85,247,0.3)] transition-all text-sm" placeholder="Enter full name" required />
          </div>
          <div>
            <label className="block text-purple-400 text-sm font-medium mb-1 font-orbitron tracking-wider text-xs">EMAIL</label>
            <input type="email" name="email" value={formData.email} onChange={(e) => setFormData({...formData, email: e.target.value})} className="w-full bg-black/50 border border-purple-500/50 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-purple-400 focus:shadow-[0_0_20px_rgba(168,85,247,0.3)] transition-all text-sm" placeholder="Enter email" required />
          </div>
          <div>
            <label className="block text-purple-400 text-sm font-medium mb-1 font-orbitron tracking-wider text-xs">PHONE</label>
            <input type="tel" name="phone" value={formData.phone} onChange={(e) => setFormData({...formData, phone: e.target.value})} className="w-full bg-black/50 border border-purple-500/50 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-purple-400 focus:shadow-[0_0_20px_rgba(168,85,247,0.3)] transition-all text-sm" placeholder="01XXXXXXXXX" required />
          </div>
          <div>
            <label className="block text-purple-400 text-sm font-medium mb-1 font-orbitron tracking-wider text-xs">PASSWORD</label>
            <input type="password" name="password" value={formData.password} onChange={(e) => setFormData({...formData, password: e.target.value})} className="w-full bg-black/50 border border-purple-500/50 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-purple-400 focus:shadow-[0_0_20px_rgba(168,85,247,0.3)] transition-all text-sm" placeholder="Min 6 characters" required />
          </div>
          <div>
            <label className="block text-purple-400 text-sm font-medium mb-1 font-orbitron tracking-wider text-xs">CONFIRM PASSWORD</label>
            <input type="password" name="confirmPassword" value={formData.confirmPassword} onChange={(e) => setFormData({...formData, confirmPassword: e.target.value})} className="w-full bg-black/50 border border-purple-500/50 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-purple-400 focus:shadow-[0_0_20px_rgba(168,85,247,0.3)] transition-all text-sm" placeholder="Confirm password" required />
          </div>
          <div>
            <label className="block text-purple-400 text-sm font-medium mb-1 font-orbitron tracking-wider text-xs">REFERRAL CODE</label>
            <input type="text" name="referralCode" value={formData.referralCode} onChange={(e) => setFormData({...formData, referralCode: e.target.value})} className="w-full bg-black/50 border border-purple-500/50 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-purple-400 focus:shadow-[0_0_20px_rgba(168,85,247,0.3)] transition-all text-sm" placeholder="Optional" />
          </div>

          <button type="submit" disabled={loading} className="w-full bg-gradient-to-r from-purple-500 via-pink-500 to-cyan-500 text-white py-3 rounded-xl font-bold font-orbitron tracking-wider hover:shadow-[0_0_30px_rgba(168,85,247,0.5)] transition-all duration-300 disabled:opacity-50">
            {loading ? 'INITIALIZING...' : 'ACTIVATE'}
          </button>
        </form>

        <p className="text-center mt-4 text-gray-400 text-sm">
          Already have account?{' '}
          <Link to="/login" className="text-purple-400 hover:text-purple-300 font-bold font-orbitron">
            ACCESS
          </Link>
        </p>
      </div>
    </div>
  )
}

export default Register