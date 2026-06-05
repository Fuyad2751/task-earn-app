import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import authService from '../services/authService'

function Login() {
  const [formData, setFormData] = useState({ email: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await authService.login(formData)
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#0a0a0a] bg-grid flex items-center justify-center p-4 relative overflow-hidden">
      {/* Animated Background */}
      <div className="absolute top-0 left-0 w-full h-full">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500 rounded-full blur-[128px] opacity-20 animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500 rounded-full blur-[128px] opacity-20 animate-pulse delay-1000"></div>
      </div>

      <div className="glass-dark rounded-3xl w-full max-w-md p-8 relative z-10 border border-cyan-500/30 neon-border text-cyan-400">
        {/* Logo */}
        <div className="text-center mb-8">
          <h1 className="text-5xl font-bold font-orbitron text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 neon-text">
            TASK<span className="text-white">EARN</span>
          </h1>
          <p className="text-gray-400 mt-2">Welcome to the future of earning</p>
        </div>

        {error && (
          <div className="bg-red-500/20 border border-red-500 text-red-400 px-4 py-3 rounded-xl mb-6 text-sm flex items-center gap-2">
            <span>⚠️</span> {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-cyan-400 text-sm font-medium mb-2 font-orbitron tracking-wider">EMAIL</label>
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={(e) => setFormData({...formData, email: e.target.value})}
              className="w-full bg-black/50 border border-cyan-500/50 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-cyan-400 focus:shadow-[0_0_20px_rgba(0,255,255,0.3)] transition-all"
              placeholder="Enter your email"
              required
            />
          </div>

          <div>
            <label className="block text-cyan-400 text-sm font-medium mb-2 font-orbitron tracking-wider">PASSWORD</label>
            <input
              type="password"
              name="password"
              value={formData.password}
              onChange={(e) => setFormData({...formData, password: e.target.value})}
              className="w-full bg-black/50 border border-cyan-500/50 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-cyan-400 focus:shadow-[0_0_20px_rgba(0,255,255,0.3)] transition-all"
              placeholder="Enter your password"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-cyan-500 via-purple-500 to-pink-500 text-white py-4 rounded-xl font-bold font-orbitron tracking-wider hover:shadow-[0_0_30px_rgba(0,255,255,0.5)] transition-all duration-300 disabled:opacity-50 text-lg"
          >
            {loading ? 'CONNECTING...' : 'ACCESS'}
          </button>
        </form>

        <p className="text-center mt-6 text-gray-400">
          New here?{' '}
          <Link to="/register" className="text-cyan-400 hover:text-cyan-300 font-bold font-orbitron">
            CREATE ACCOUNT
          </Link>
        </p>
      </div>
    </div>
  )
}

export default Login