import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import authService from '../services/authService'

function Dashboard() {
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

  const handleLogout = () => {
    authService.logout()
    navigate('/login')
  }

  if (!user) return null

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Navbar */}
      <nav className="bg-white shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-blue-600">TaskEarn</h1>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={() => navigate('/packages')}
                className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium"
              >
                Packages
              </button>
              <button
                onClick={() => navigate('/tasks')}
                className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium"
              >
                Tasks
              </button>
              <button
                onClick={() => navigate('/profile')}
                className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium"
              >
                Profile
              </button>
              <button
                onClick={handleLogout}
                className="bg-red-500 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-red-600"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <h2 className="text-2xl font-bold text-gray-800 mb-6">
            Welcome back, {user.fullName}!
          </h2>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-gray-600">Current Balance</h3>
              <p className="text-3xl font-bold text-blue-600 mt-2">৳{user.balance || 0}</p>
            </div>
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-gray-600">Total Earnings</h3>
              <p className="text-3xl font-bold text-green-600 mt-2">৳{user.totalEarnings || 0}</p>
            </div>
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-gray-600">Completed Tasks</h3>
              <p className="text-3xl font-bold text-purple-600 mt-2">{user.completedTasks || 0}</p>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-xl font-bold text-gray-800 mb-4">Quick Actions</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <button
                onClick={() => navigate('/tasks')}
                className="bg-blue-600 text-white p-4 rounded-lg hover:bg-blue-700 transition"
              >
                View Tasks
              </button>
              <button
                onClick={() => navigate('/packages')}
                className="bg-green-600 text-white p-4 rounded-lg hover:bg-green-700 transition"
              >
                Buy Package
              </button>
              <button
                onClick={() => navigate('/profile')}
                className="bg-purple-600 text-white p-4 rounded-lg hover:bg-purple-700 transition"
              >
                My Profile
              </button>
              <button className="bg-orange-600 text-white p-4 rounded-lg hover:bg-orange-700 transition">
                Withdraw
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard