import { useNavigate } from 'react-router-dom'

function Tasks() {
  const navigate = useNavigate()

  const tasks = [
    { id: 1, title: 'YouTube Video Watch', reward: 10, type: 'youtube', timeLimit: '10 min' },
    { id: 2, title: 'Facebook Page Like', reward: 5, type: 'facebook', timeLimit: '5 min' },
    { id: 3, title: 'Instagram Follow', reward: 8, type: 'instagram', timeLimit: '5 min' },
    { id: 4, title: 'Website Visit', reward: 15, type: 'website', timeLimit: '15 min' },
    { id: 5, title: 'App Download', reward: 20, type: 'app', timeLimit: '20 min' },
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
              <button onClick={() => navigate('/packages')} className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium">Packages</button>
              <button onClick={() => navigate('/profile')} className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium">Profile</button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto py-12 px-4 sm:px-6 lg:px-8">
        <h2 className="text-3xl font-bold text-gray-800 mb-8">Available Tasks</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {tasks.map((task) => (
            <div key={task.id} className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition">
              <div className="flex justify-between items-start mb-4">
                <h3 className="text-lg font-semibold text-gray-800">{task.title}</h3>
                <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs font-semibold">
                  ৳{task.reward}
                </span>
              </div>
              <div className="flex justify-between items-center text-sm text-gray-500 mb-4">
                <span>Type: {task.type}</span>
                <span>Time: {task.timeLimit}</span>
              </div>
              <button className="w-full bg-blue-600 text-white py-2 rounded-lg font-semibold hover:bg-blue-700 transition">
                Start Task
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default Tasks