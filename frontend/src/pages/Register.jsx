import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import authService from '../services/authService'

function Register() {
  const [formData, setFormData] = useState({
    fullName: '', email: '', phone: '', password: '', confirmPassword: '', referralCode: ''
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [step, setStep] = useState(1)
  const navigate = useNavigate()

  const nextStep = () => {
    if (step === 1) {
      if (!formData.fullName || !formData.email || !formData.phone) {
        setError('Please fill all required fields')
        return
      }
      setError('')
      setStep(2)
    }
  }

  const prevStep = () => {
    setStep(1)
    setError('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match')
      return
    }
    if (formData.password.length < 6) {
      setError('Password must be at least 6 characters')
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
    <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center p-4 relative overflow-hidden">
      {/* 3D Animated Background */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-[600px] h-[600px] bg-gradient-to-br from-purple-500/30 to-pink-600/20 rounded-full blur-[120px] animate-pulse" 
          style={{transform: 'rotateX(60deg) rotateZ(-45deg) scale(1.5)', transformStyle: 'preserve-3d'}}></div>
        <div className="absolute bottom-1/4 right-1/4 w-[600px] h-[600px] bg-gradient-to-tl from-cyan-500/30 to-blue-600/20 rounded-full blur-[120px] animate-pulse" 
          style={{animationDelay: '1s', transform: 'rotateX(60deg) rotateZ(45deg) scale(1.5)', transformStyle: 'preserve-3d'}}></div>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-gradient-to-r from-pink-500/10 via-transparent to-cyan-500/10 rounded-full blur-[150px]"
          style={{transform: 'rotateX(45deg) scale(2)', transformStyle: 'preserve-3d'}}></div>
      </div>

      {/* Grid Pattern */}
      <div className="absolute inset-0 opacity-20" style={{
        backgroundImage: `linear-gradient(rgba(168, 85, 247, 0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(168, 85, 247, 0.3) 1px, transparent 1px)`,
        backgroundSize: '80px 80px',
        transform: 'perspective(1000px) rotateX(60deg) scale(2)',
        transformStyle: 'preserve-3d'
      }}></div>

      {/* Floating Particles */}
      {[...Array(30)].map((_, i) => (
        <div key={i} className="absolute w-1.5 h-1.5 bg-purple-400 rounded-full animate-pulse"
          style={{
            left: `${Math.random() * 100}%`,
            top: `${Math.random() * 100}%`,
            animationDelay: `${Math.random() * 3}s`,
            boxShadow: '0 0 10px rgba(168,85,247,0.8), 0 0 20px rgba(168,85,247,0.4)'
          }}></div>
      ))}

      {/* Main Card */}
      <div className="relative z-10 w-full max-w-lg" style={{perspective: '1000px'}}>
        <div className="bg-gradient-to-br from-gray-900/95 to-gray-800/95 backdrop-blur-2xl rounded-3xl p-10 border border-purple-500/30 shadow-2xl max-h-[90vh] overflow-y-auto"
          style={{
            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 30px rgba(168,85,247,0.1), inset 0 1px 0 rgba(255,255,255,0.1)',
            transformStyle: 'preserve-3d'
          }}>
          
          {/* Logo Section */}
          <div className="text-center mb-10" style={{transform: 'translateZ(30px)'}}>
            <div className="inline-block relative mb-6">
              <div className="w-20 h-20 bg-gradient-to-br from-purple-500 to-pink-600 rounded-2xl flex items-center justify-center transform rotate-45 shadow-[0_0_30px_rgba(168,85,247,0.5)] mx-auto">
                <span className="text-3xl font-bold text-white transform -rotate-45">+</span>
              </div>
            </div>
            <h1 className="text-5xl font-black text-white mb-2 tracking-tight">
              Join <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-500">TaskEarn</span>
            </h1>
            <p className="text-gray-400 text-lg">Begin your earning journey</p>
            
            {/* Step Indicator */}
            <div className="flex justify-center gap-3 mt-6">
              <div className={`h-2 w-12 rounded-full transition-all ${step === 1 ? 'bg-purple-500 shadow-[0_0_10px_rgba(168,85,247,0.5)]' : 'bg-gray-700'}`}></div>
              <div className={`h-2 w-12 rounded-full transition-all ${step === 2 ? 'bg-purple-500 shadow-[0_0_10px_rgba(168,85,247,0.5)]' : 'bg-gray-700'}`}></div>
            </div>
          </div>

          {error && (
            <div className="bg-red-500/10 border border-red-500/50 text-red-400 px-5 py-4 rounded-2xl mb-6 flex items-center gap-3 backdrop-blur-sm"
              style={{transform: 'translateZ(20px)'}}>
              <span className="text-xl">⚠️</span>
              <span className="text-sm">{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5" style={{transform: 'translateZ(20px)'}}>
            {step === 1 && (
              <>
                <div className="space-y-2">
                  <label className="block text-purple-400 text-xs font-bold uppercase tracking-widest">Full Name *</label>
                  <div className="relative group">
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-500 to-pink-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition-opacity"></div>
                    <div className="relative">
                      <span className="absolute left-4 top-1/2 -translate-y-1/2 text-purple-400 text-lg">👤</span>
                      <input type="text" name="fullName" value={formData.fullName} onChange={(e) => setFormData({...formData, fullName: e.target.value})}
                        className="w-full bg-gray-900/80 border border-gray-700 rounded-xl pl-12 pr-4 py-4 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500 transition-all" placeholder="Enter your full name" required />
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="block text-purple-400 text-xs font-bold uppercase tracking-widest">Email Address *</label>
                  <div className="relative group">
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-500 to-pink-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition-opacity"></div>
                    <div className="relative">
                      <span className="absolute left-4 top-1/2 -translate-y-1/2 text-purple-400 text-lg">@</span>
                      <input type="email" name="email" value={formData.email} onChange={(e) => setFormData({...formData, email: e.target.value})}
                        className="w-full bg-gray-900/80 border border-gray-700 rounded-xl pl-12 pr-4 py-4 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500 transition-all" placeholder="Enter your email" required />
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="block text-purple-400 text-xs font-bold uppercase tracking-widest">Phone Number *</label>
                  <div className="relative group">
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-500 to-pink-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition-opacity"></div>
                    <div className="relative">
                      <span className="absolute left-4 top-1/2 -translate-y-1/2 text-purple-400 text-lg">📱</span>
                      <input type="tel" name="phone" value={formData.phone} onChange={(e) => setFormData({...formData, phone: e.target.value})}
                        className="w-full bg-gray-900/80 border border-gray-700 rounded-xl pl-12 pr-4 py-4 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500 transition-all" placeholder="01XXXXXXXXX" required />
                    </div>
                  </div>
                </div>

                <button type="button" onClick={nextStep}
                  className="w-full relative group">
                  <div className="absolute inset-0 bg-gradient-to-r from-purple-500 to-pink-600 rounded-xl blur opacity-75 group-hover:opacity-100 transition-opacity"></div>
                  <div className="relative bg-gradient-to-r from-purple-500 to-pink-600 text-white py-5 rounded-xl font-bold text-lg tracking-wider hover:scale-[1.02] transition-transform flex items-center justify-center gap-2">
                    NEXT STEP <span>→</span>
                  </div>
                </button>
              </>
            )}

            {step === 2 && (
              <>
                <div className="space-y-2">
                  <label className="block text-purple-400 text-xs font-bold uppercase tracking-widest">Password *</label>
                  <div className="relative group">
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-500 to-pink-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition-opacity"></div>
                    <div className="relative">
                      <span className="absolute left-4 top-1/2 -translate-y-1/2 text-purple-400 text-lg">🔒</span>
                      <input type="password" name="password" value={formData.password} onChange={(e) => setFormData({...formData, password: e.target.value})}
                        className="w-full bg-gray-900/80 border border-gray-700 rounded-xl pl-12 pr-4 py-4 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500 transition-all" placeholder="Minimum 6 characters" required />
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="block text-purple-400 text-xs font-bold uppercase tracking-widest">Confirm Password *</label>
                  <div className="relative group">
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-500 to-pink-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition-opacity"></div>
                    <div className="relative">
                      <span className="absolute left-4 top-1/2 -translate-y-1/2 text-purple-400 text-lg">✅</span>
                      <input type="password" name="confirmPassword" value={formData.confirmPassword} onChange={(e) => setFormData({...formData, confirmPassword: e.target.value})}
                        className="w-full bg-gray-900/80 border border-gray-700 rounded-xl pl-12 pr-4 py-4 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500 transition-all" placeholder="Confirm your password" required />
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="block text-purple-400 text-xs font-bold uppercase tracking-widest">Referral Code</label>
                  <div className="relative group">
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-500 to-pink-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition-opacity"></div>
                    <div className="relative">
                      <span className="absolute left-4 top-1/2 -translate-y-1/2 text-purple-400 text-lg">🎁</span>
                      <input type="text" name="referralCode" value={formData.referralCode} onChange={(e) => setFormData({...formData, referralCode: e.target.value})}
                        className="w-full bg-gray-900/80 border border-gray-700 rounded-xl pl-12 pr-4 py-4 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500 transition-all" placeholder="Optional referral code" />
                    </div>
                  </div>
                </div>

                <div className="flex gap-3">
                  <button type="button" onClick={prevStep}
                    className="flex-1 bg-gray-800 border border-gray-700 text-gray-300 py-5 rounded-xl font-bold text-lg hover:bg-gray-700 transition-colors">
                    ← BACK
                  </button>
                  <button type="submit" disabled={loading}
                    className="flex-1 relative group disabled:opacity-50">
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-500 to-pink-600 rounded-xl blur opacity-75 group-hover:opacity-100 transition-opacity"></div>
                    <div className="relative bg-gradient-to-r from-purple-500 to-pink-600 text-white py-5 rounded-xl font-bold text-lg tracking-wider hover:scale-[1.02] transition-transform">
                      {loading ? 'CREATING...' : 'COMPLETE 🎉'}
                    </div>
                  </button>
                </div>
              </>
            )}
          </form>

          <div className="mt-8 text-center" style={{transform: 'translateZ(10px)'}}>
            <p className="text-gray-400">
              Already have an account?{' '}
              <Link to="/login" className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-500 font-bold hover:scale-105 inline-block transition-transform">
                Sign In
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Register