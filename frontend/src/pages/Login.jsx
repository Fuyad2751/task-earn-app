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
    <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center p-4 relative overflow-hidden">
      {/* 3D Animated Background */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-[600px] h-[600px] bg-gradient-to-br from-cyan-500/30 to-blue-600/20 rounded-full blur-[120px] animate-pulse" 
          style={{transform: 'rotateX(60deg) rotateZ(-45deg) scale(1.5)', transformStyle: 'preserve-3d'}}></div>
        <div className="absolute bottom-1/4 right-1/4 w-[600px] h-[600px] bg-gradient-to-tl from-purple-500/30 to-pink-600/20 rounded-full blur-[120px] animate-pulse" 
          style={{animationDelay: '1s', transform: 'rotateX(60deg) rotateZ(45deg) scale(1.5)', transformStyle: 'preserve-3d'}}></div>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-gradient-to-r from-blue-500/10 via-transparent to-pink-500/10 rounded-full blur-[150px]"
          style={{transform: 'rotateX(45deg) scale(2)', transformStyle: 'preserve-3d'}}></div>
      </div>

      {/* Grid Pattern */}
      <div className="absolute inset-0 opacity-20" style={{
        backgroundImage: `linear-gradient(rgba(0, 255, 255, 0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 255, 255, 0.3) 1px, transparent 1px)`,
        backgroundSize: '80px 80px',
        transform: 'perspective(1000px) rotateX(60deg) scale(2)',
        transformStyle: 'preserve-3d'
      }}></div>

      {/* Floating Particles */}
      {[...Array(20)].map((_, i) => (
        <div key={i} className="absolute w-1 h-1 bg-cyan-400 rounded-full animate-pulse"
          style={{
            left: `${Math.random() * 100}%`,
            top: `${Math.random() * 100}%`,
            animationDelay: `${Math.random() * 3}s`,
            boxShadow: '0 0 10px rgba(0,255,255,0.8), 0 0 20px rgba(0,255,255,0.4)'
          }}></div>
      ))}

      {/* Main Card */}
      <div className="relative z-10 w-full max-w-lg"
        style={{perspective: '1000px'}}>
        <div className="bg-gradient-to-br from-gray-900/95 to-gray-800/95 backdrop-blur-2xl rounded-3xl p-10 border border-cyan-500/30 shadow-2xl transform transition-all duration-500 hover:shadow-cyan-500/20"
          style={{
            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 30px rgba(0, 255, 255, 0.1), inset 0 1px 0 rgba(255,255,255,0.1)',
            transformStyle: 'preserve-3d'
          }}>
          
          {/* Logo Section */}
          <div className="text-center mb-10" style={{transform: 'translateZ(30px)'}}>
            <div className="inline-block relative mb-6">
              <div className="w-20 h-20 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-2xl flex items-center justify-center transform rotate-45 shadow-[0_0_30px_rgba(0,255,255,0.5)] mx-auto">
                <span className="text-3xl font-bold text-white transform -rotate-45" style={{textShadow: '0 0 20px rgba(255,255,255,0.8)'}}>T</span>
              </div>
              <div className="absolute -top-2 -right-2 w-6 h-6 bg-yellow-400 rounded-full animate-ping"></div>
            </div>
            <h1 className="text-5xl font-black text-white mb-2 tracking-tight" 
              style={{textShadow: '0 0 30px rgba(0,255,255,0.5), 0 0 60px rgba(0,255,255,0.3)'}}>
              Task<span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">Earn</span>
            </h1>
            <p className="text-gray-400 text-lg">Welcome back to the future</p>
          </div>

          {error && (
            <div className="bg-red-500/10 border border-red-500/50 text-red-400 px-5 py-4 rounded-2xl mb-6 flex items-center gap-3 backdrop-blur-sm"
              style={{transform: 'translateZ(20px)'}}>
              <span className="text-xl">⚠️</span>
              <span className="text-sm">{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6" style={{transform: 'translateZ(20px)'}}>
            <div className="space-y-2">
              <label className="block text-cyan-400 text-xs font-bold uppercase tracking-widest">Email Address</label>
              <div className="relative group">
                <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition-opacity"></div>
                <div className="relative">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-400 text-lg">@</span>
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={(e) => setFormData({...formData, email: e.target.value})}
                    className="w-full bg-gray-900/80 border border-gray-700 rounded-xl pl-12 pr-4 py-4 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition-all focus:shadow-[0_0_20px_rgba(0,255,255,0.2)]"
                    placeholder="Enter your email"
                    required
                  />
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <label className="block text-cyan-400 text-xs font-bold uppercase tracking-widest">Password</label>
              <div className="relative group">
                <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition-opacity"></div>
                <div className="relative">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-400 text-lg">🔒</span>
                  <input
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={(e) => setFormData({...formData, password: e.target.value})}
                    className="w-full bg-gray-900/80 border border-gray-700 rounded-xl pl-12 pr-4 py-4 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition-all focus:shadow-[0_0_20px_rgba(0,255,255,0.2)]"
                    placeholder="Enter your password"
                    required
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between text-sm">
              <label className="flex items-center gap-2 text-gray-400 cursor-pointer">
                <input type="checkbox" className="rounded border-gray-600 bg-gray-800 text-cyan-500 focus:ring-cyan-500" />
                <span>Remember me</span>
              </label>
              <a href="#" className="text-cyan-400 hover:text-cyan-300 transition-colors font-medium">Forgot Password?</a>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full relative group disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-600 rounded-xl blur opacity-75 group-hover:opacity-100 transition-opacity"></div>
              <div className="relative bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-600 text-white py-5 rounded-xl font-bold text-lg tracking-wider hover:scale-[1.02] transition-transform flex items-center justify-center gap-2"
                style={{textShadow: '0 2px 4px rgba(0,0,0,0.3)'}}>
                {loading ? (
                  <>
                    <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none"/>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                    </svg>
                    CONNECTING...
                  </>
                ) : (
                  <>
                    <span>🚀</span> ACCESS DASHBOARD
                  </>
                )}
              </div>
            </button>
          </form>

          <div className="mt-8 text-center" style={{transform: 'translateZ(10px)'}}>
            <p className="text-gray-400">
              Don't have an account?{' '}
              <Link to="/register" className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 font-bold hover:scale-105 inline-block transition-transform">
                Create New Account
              </Link>
            </p>
          </div>

          {/* Social Login */}
          <div className="mt-6 flex gap-3 justify-center" style={{transform: 'translateZ(10px)'}}>
            {['google', 'facebook', 'github'].map((platform) => (
              <button key={platform} className="w-12 h-12 bg-gray-800/80 border border-gray-700 rounded-xl flex items-center justify-center hover:border-cyan-500/50 hover:shadow-[0_0_15px_rgba(0,255,255,0.2)] transition-all">
                <span className="text-xl">{platform === 'google' ? 'G' : platform === 'facebook' ? 'f' : '⌨'}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default Login