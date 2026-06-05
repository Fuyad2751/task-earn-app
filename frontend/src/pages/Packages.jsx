import { useNavigate } from 'react-router-dom'

function Packages() {
  const navigate = useNavigate()

  const packages = [
    {
      id: 1,
      name: 'Basic',
      price: 500,
      dailyTasks: 5,
      dailyEarning: 50,
      referralBonus: 10,
      color: 'bg-blue-500',
      features: ['5 Daily Tasks', 'Earn up to ৳50/day', 'Basic Support', 'Referral Bonus ৳10']
    },
    {
      id: 2,
      name: 'Silver',
      price: 1000,
      dailyTasks: 10,
      dailyEarning: 120,
      referralBonus: 25,
      color: 'bg-gray-500',
      features: ['10 Daily Tasks', 'Earn up to ৳120/day', 'Priority Support', 'Referral Bonus ৳25']
    },
    {
      id: 3,
      name: 'Gold',
      price: 2000,
      dailyTasks: 20,
      dailyEarning: 300,
      referralBonus: 50,
      color: 'bg-yellow-500',
      features: ['20 Daily Tasks', 'Earn up to ৳300/day', 'Premium Support', 'Referral Bonus ৳50', 'Instant Withdrawal']
    }
  ]

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
              <button onClick={() => navigate('/tasks')} className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium">Tasks</button>
              <button onClick={() => navigate('/profile')} className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium">Profile</button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto py-12 px-4 sm:px-6 lg:px-8">
        <h2 className="text-3xl font-bold text-gray-800 mb-8 text-center">Choose Your Package</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {packages.map((pkg) => (
            <div key={pkg.id} className="bg-white rounded-xl shadow-lg overflow-hidden">
              <div className={`${pkg.color} p-6 text-white`}>
                <h3 className="text-2xl font-bold">{pkg.name}</h3>
                <p className="text-4xl font-bold mt-4">৳{pkg.price}</p>
                <p className="text-sm mt-1">One time payment</p>
              </div>
              <div className="p-6">
                <ul className="space-y-3 mb-6">
                  {pkg.features.map((feature, index) => (
                    <li key={index} className="flex items-center text-gray-700">
                      <span className="text-green-500 mr-2">✓</span>
                      {feature}
                    </li>
                  ))}
                </ul>
                <button className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition duration-300">
                  Purchase Now
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default Packages