import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import authService from '../services/authService'

function Profile() {
  const [user, setUser] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    const userData = authService.getCurrentUser()
    if (!userData) {
      navigate('/login')
    } else {
      setUser(userData)
    }
  }, [navigate])

  if (!user) return null

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-blue-600">TaskEarn</h1>
            </div>
            <div className="flex items-center space-x-4">
              <button onClick={() => navigate('/dashboard')} className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium">Dashboard</button>
              <button onClick={() => navigate('/packages')} className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium">Packages</button>
              <button onClick={() => navigate('/tasks')} className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium">Tasks</button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-3xl mx-auto py-12 px-4 sm:px-6 lg:px-8">
        <div className="bg-white rounded-xl shadow-lg overflow-hidden">
          <div className="bg-blue-600 p-8 text-white">
            <div className="flex items-center space-x-4">
              <div className="w-20 h-20 bg-white rounded-full flex items-center justify-center text-blue-600 text-2xl font-bold">
                {user.fullName?.charAt(0)}
              </div>
              <div>
                <h2 className="text-2xl font-bold">{user.fullName}</h2>
                <p className="text-blue-100">{user.email}</p>
              </div>
            </div>
          </div>
          
          <div className="p-8">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-500">Full Name</label>
                <p className="mt-1 text-lg text-gray-800">{user.fullName}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Email</label>
                <p className="mt-1 text-lg text-gray-800">{user.email}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Phone</label>
                <p className="mt-1 text-lg text-gray-800">{user.phone || 'Not provided'}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Referral Code</label>
                <p className="mt-1 text-lg text-gray-800">{user.referralCode || 'N/A'}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Current Balance</label>
                <p className="mt-1 text-lg text-green-600 font-bold">৳{user.balance || 0}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Total Earnings</label>
                <p className="mt-1 text-lg text-blue-600 font-bold">৳{user.totalEarnings || 0}</p>
              </div>
            </div>

            <div className="mt-8 border-t pt-6">
              <button className="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition mr-4">
                Edit Profile
              </button>
              <button className="bg-green-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-green-700 transition">
                Withdraw Money
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Profile