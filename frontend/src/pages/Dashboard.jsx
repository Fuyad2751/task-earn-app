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

  const handleAddMoney = () => {
    if (!amount || amount < 100) {
      setMessage('Minimum amount is ৳100')
      return
    }
    setMessage(`Please send ৳${amount} to our ${paymentMethod} number: 01XXXXXXXXX`)
    setShowAddMoney(false)
    setAmount('')
  }

  const handleWithdraw = () => {
    if (!amount || amount < 100) {
      setMessage('Minimum withdrawal is ৳100')
      return
    }
    if (!accountNumber) {
      setMessage('Please enter your account number')
      return
    }
    setMessage(`Withdrawal request of ৳${amount} submitted successfully!`)
    setShowWithdraw(false)
    setAmount('')
    setAccountNumber('')
  }

  if (!user) return null

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Navbar */}
      <nav className="bg-white shadow-md">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-blue-600">TaskEarn</h1>
            </div>
            <div className="flex items-center space-x-4">
              <button onClick={() => navigate('/packages')} className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium">Packages</button>
              <button onClick={() => navigate('/tasks')} className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium">Tasks</button>
              <button onClick={() => navigate('/profile')} className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium">Profile</button>
              <button onClick={handleLogout} className="bg-red-500 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-red-600">Logout</button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto py-6 px-4">
        <h2 className="text-2xl font-bold text-gray-800 mb-6">Welcome, {user.fullName}!</h2>

        {message && (
          <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg mb-4">
            {message}
            <button onClick={() => setMessage('')} className="float-right font-bold">&times;</button>
          </div>
        )}

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

        {/* Add Money & Withdraw Buttons */}
        <div className="grid grid-cols-2 gap-4 mb-8">
          <button
            onClick={() => setShowAddMoney(true)}
            className="bg-green-600 text-white py-4 rounded-xl font-bold text-lg hover:bg-green-700 transition shadow-lg"
          >
            💰 Add Money
          </button>
          <button
            onClick={() => setShowWithdraw(true)}
            className="bg-orange-600 text-white py-4 rounded-xl font-bold text-lg hover:bg-orange-700 transition shadow-lg"
          >
            💸 Withdraw
          </button>
        </div>

        {/* Add Money Modal */}
        {showAddMoney && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-2xl p-8 w-full max-w-md mx-4">
              <h3 className="text-2xl font-bold text-gray-800 mb-6">Add Money</h3>
              
              <div className="mb-4">
                <label className="block text-gray-700 text-sm font-semibold mb-2">Amount (৳)</label>
                <input
                  type="number"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-green-500"
                  placeholder="Enter amount (min ৳100)"
                />
              </div>

              <div className="mb-6">
                <label className="block text-gray-700 text-sm font-semibold mb-2">Payment Method</label>
                <select
                  value={paymentMethod}
                  onChange={(e) => setPaymentMethod(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-green-500"
                >
                  <option value="bkash">bKash</option>
                  <option value="nagad">Nagad</option>
                  <option value="rocket">Rocket</option>
                  <option value="bank">Bank Transfer</option>
                </select>
              </div>

              <div className="flex space-x-3">
                <button
                  onClick={handleAddMoney}
                  className="flex-1 bg-green-600 text-white py-3 rounded-xl font-semibold hover:bg-green-700"
                >
                  Confirm
                </button>
                <button
                  onClick={() => setShowAddMoney(false)}
                  className="flex-1 bg-gray-300 text-gray-700 py-3 rounded-xl font-semibold hover:bg-gray-400"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Withdraw Modal */}
        {showWithdraw && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-2xl p-8 w-full max-w-md mx-4">
              <h3 className="text-2xl font-bold text-gray-800 mb-6">Withdraw Money</h3>
              
              <div className="mb-4">
                <label className="block text-gray-700 text-sm font-semibold mb-2">Amount (৳)</label>
                <input
                  type="number"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-orange-500"
                  placeholder="Enter amount (min ৳100)"
                />
                <p className="text-sm text-gray-500 mt-1">Available Balance: ৳{user.balance || 0}</p>
              </div>

              <div className="mb-4">
                <label className="block text-gray-700 text-sm font-semibold mb-2">Payment Method</label>
                <select
                  value={paymentMethod}
                  onChange={(e) => setPaymentMethod(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-orange-500"
                >
                  <option value="bkash">bKash</option>
                  <option value="nagad">Nagad</option>
                  <option value="rocket">Rocket</option>
                  <option value="bank">Bank Transfer</option>
                </select>
              </div>

              <div className="mb-6">
                <label className="block text-gray-700 text-sm font-semibold mb-2">Account Number</label>
                <input
                  type="text"
                  value={accountNumber}
                  onChange={(e) => setAccountNumber(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-orange-500"
                  placeholder="Enter your account number"
                />
              </div>

              <div className="flex space-x-3">
                <button
                  onClick={handleWithdraw}
                  className="flex-1 bg-orange-600 text-white py-3 rounded-xl font-semibold hover:bg-orange-700"
                >
                  Submit
                </button>
                <button
                  onClick={() => setShowWithdraw(false)}
                  className="flex-1 bg-gray-300 text-gray-700 py-3 rounded-xl font-semibold hover:bg-gray-400"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-xl font-bold text-gray-800 mb-4">Quick Actions</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <button onClick={() => navigate('/tasks')} className="bg-blue-600 text-white p-4 rounded-lg hover:bg-blue-700 transition">View Tasks</button>
            <button onClick={() => navigate('/packages')} className="bg-green-600 text-white p-4 rounded-lg hover:bg-green-700 transition">Buy Package</button>
            <button onClick={() => navigate('/profile')} className="bg-purple-600 text-white p-4 rounded-lg hover:bg-purple-700 transition">My Profile</button>
            <button onClick={() => setShowWithdraw(true)} className="bg-orange-600 text-white p-4 rounded-lg hover:bg-orange-700 transition">Withdraw</button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard