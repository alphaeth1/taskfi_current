'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import {
  Users,
  Briefcase,
  DollarSign,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Activity,
  Shield,
  Settings,
  FileText,
  Eye,
  Clock,
  CheckCircle,
  XCircle,
  BarChart3,
  PieChart,
  ArrowUpRight,
  ArrowDownRight,
  Plus,
  Edit3,
  Trash2,
} from 'lucide-react'

interface DashboardStats {
  overview: {
    totalUsers: number
    averageRating: number
    userGrowth: {
      last30Days: number
      last7Days: number
      lastDay: number
    }
    roleBreakdown: {
      FREELANCER: number
      HIRER: number
      ADMIN: number
    }
    healthScore: number
  }
  jobs: {
    total: number
    successRate: number
    byStatus: Record<string, { count: number; budget: number }>
  }
  gigs: {
    total: number
    totalOrders: number
    byStatus: Record<string, { count: number; orders: number }>
  }
  finance: {
    totalVolume: number
    totalTransactions: number
    byStatus: Record<string, { count: number; volume: number }>
  }
  urgent: {
    disputedPayments: any[]
    disputeCount: number
  }
  health: {
    activeUsers: number
    inactiveUsers: number
    verifiedUsers: number
    openJobs: number
    inProgressJobs: number
    activeGigs: number
    escrowPayments: number
    disputedPayments: number
    score: number
  }
}

export default function AdminDashboard() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [recentUsers, setRecentUsers] = useState<any[]>([])
  const [recentJobs, setRecentJobs] = useState<any[]>([])

  useEffect(() => {
    if (status === 'loading') return

    if (!session) {
      router.push('/auth/signin?callbackUrl=/dashboard/admin')
      return
    }

    if (session.user.role !== 'ADMIN') {
      router.push('/dashboard')
      return
    }

    fetchDashboardData()
  }, [session, status, router])

  const fetchDashboardData = async () => {
    try {
      const response = await fetch('/api/admin/dashboard')
      
      if (response.ok) {
        const data = await response.json()
        setStats(data)
        setRecentUsers(data.recent?.users || [])
        setRecentJobs(data.recent?.jobs || [])
      } else {
        console.error('Failed to fetch admin dashboard data')
      }
    } catch (error) {
      console.error('Error fetching admin dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  const getHealthScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600 dark:text-green-400'
    if (score >= 60) return 'text-yellow-600 dark:text-yellow-400'
    return 'text-red-600 dark:text-red-400'
  }

  const getStatusBadge = (status: string) => {
    const statusStyles = {
      OPEN: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      IN_PROGRESS: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
      COMPLETED: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      ACTIVE: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      PAUSED: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
      INACTIVE: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200',
      DISPUTED: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
      ESCROW: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      RELEASED: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
    }

    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusStyles[status as keyof typeof statusStyles] || statusStyles.INACTIVE}`}>
        {status.replace('_', ' ')}
      </span>
    )
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-purple-50 to-blue-50 dark:from-purple-950 dark:to-blue-950 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600"></div>
      </div>
    )
  }

  if (!stats) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-purple-50 to-blue-50 dark:from-purple-950 dark:to-blue-950 flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">Failed to load dashboard</h2>
          <p className="text-gray-600 dark:text-gray-400">Please try refreshing the page</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 to-blue-50 dark:from-purple-950 dark:to-blue-950">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Admin Dashboard
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Monitor platform health, manage users, and oversee operations
          </p>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Users</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {stats.overview.totalUsers.toLocaleString()}
                </p>
                <div className="flex items-center mt-2 text-sm">
                  <ArrowUpRight className="w-4 h-4 text-green-500 mr-1" />
                  <span className="text-green-600 dark:text-green-400">
                    +{stats.overview.userGrowth.last30Days} this month
                  </span>
                </div>
              </div>
              <div className="bg-blue-100 dark:bg-blue-900 p-3 rounded-lg">
                <Users className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Platform Health</p>
                <p className={`text-2xl font-bold ${getHealthScoreColor(stats.overview.healthScore)}`}>
                  {stats.overview.healthScore}/100
                </p>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                  {stats.overview.healthScore >= 80 ? 'Excellent' : stats.overview.healthScore >= 60 ? 'Good' : 'Needs Attention'}
                </p>
              </div>
              <div className="bg-green-100 dark:bg-green-900 p-3 rounded-lg">
                <Activity className="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Volume</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  ${stats.finance.totalVolume.toLocaleString()}
                </p>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                  {stats.finance.totalTransactions.toLocaleString()} transactions
                </p>
              </div>
              <div className="bg-green-100 dark:bg-green-900 p-3 rounded-lg">
                <DollarSign className="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Issues</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {stats.urgent.disputeCount}
                </p>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                  Disputed payments
                </p>
              </div>
              <div className={`p-3 rounded-lg ${stats.urgent.disputeCount > 0 ? 'bg-red-100 dark:bg-red-900' : 'bg-gray-100 dark:bg-gray-700'}`}>
                <AlertTriangle className={`w-6 h-6 ${stats.urgent.disputeCount > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-400'}`} />
              </div>
            </div>
          </div>
        </div>

        {/* Urgent Alerts */}
        {stats.urgent.disputeCount > 0 && (
          <div className="mb-8 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <AlertTriangle className="w-6 h-6 text-red-600 dark:text-red-400" />
                <div>
                  <h3 className="text-lg font-semibold text-red-900 dark:text-red-100">
                    Payment Disputes Require Attention
                  </h3>
                  <p className="text-red-700 dark:text-red-300 mt-1">
                    {stats.urgent.disputeCount} payment{stats.urgent.disputeCount !== 1 ? 's' : ''} currently disputed and awaiting resolution
                  </p>
                </div>
              </div>
              <button 
                onClick={() => router.push('/dashboard/admin/disputes')}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors"
              >
                Resolve Disputes
              </button>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-8">
            
            {/* Platform Overview */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">User Breakdown</h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-400">Freelancers</span>
                    <span className="font-semibold text-gray-900 dark:text-white">
                      {stats.overview.roleBreakdown.FREELANCER?.toLocaleString() || 0}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-400">Hirers</span>
                    <span className="font-semibold text-gray-900 dark:text-white">
                      {stats.overview.roleBreakdown.HIRER?.toLocaleString() || 0}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-400">Admins</span>
                    <span className="font-semibold text-gray-900 dark:text-white">
                      {stats.overview.roleBreakdown.ADMIN?.toLocaleString() || 0}
                    </span>
                  </div>
                  <div className="pt-3 border-t border-gray-200 dark:border-gray-700">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-600 dark:text-gray-400">Verified Users</span>
                      <span className="font-semibold text-green-600 dark:text-green-400">
                        {stats.health.verifiedUsers.toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Platform Activity</h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-400">Active Jobs</span>
                    <span className="font-semibold text-blue-600 dark:text-blue-400">
                      {(stats.health.openJobs + stats.health.inProgressJobs).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-400">Active Gigs</span>
                    <span className="font-semibold text-purple-600 dark:text-purple-400">
                      {stats.health.activeGigs.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-400">Escrow Payments</span>
                    <span className="font-semibold text-yellow-600 dark:text-yellow-400">
                      {stats.health.escrowPayments.toLocaleString()}
                    </span>
                  </div>
                  <div className="pt-3 border-t border-gray-200 dark:border-gray-700">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-600 dark:text-gray-400">Success Rate</span>
                      <span className="font-semibold text-green-600 dark:text-green-400">
                        {stats.jobs.successRate.toFixed(1)}%
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Activity */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Users</h3>
                  <button 
                    onClick={() => router.push('/dashboard/admin/users')}
                    className="text-purple-600 hover:text-purple-800 dark:text-purple-400 dark:hover:text-purple-200 font-medium"
                  >
                    Manage Users
                  </button>
                </div>
              </div>
              
              <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {recentUsers.slice(0, 5).map((user) => (
                  <div key={user.id} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        {user.avatarUrl && (
                          <img 
                            src={user.avatarUrl} 
                            alt={user.name}
                            className="w-10 h-10 rounded-full"
                          />
                        )}
                        <div>
                          <div className="font-medium text-gray-900 dark:text-white">
                            {user.name} (@{user.username})
                          </div>
                          <div className="text-sm text-gray-600 dark:text-gray-400">
                            Joined {new Date(user.createdAt).toLocaleDateString()}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        {getStatusBadge(user.role)}
                        {user.isVerified && (
                          <CheckCircle className="w-4 h-4 text-green-500" />
                        )}
                        <button 
                          onClick={() => router.push(`/dashboard/admin/users/${user.id}`)}
                          className="p-1 text-gray-400 hover:text-purple-600 dark:hover:text-purple-400"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recent Jobs */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Jobs</h3>
                  <button 
                    onClick={() => router.push('/dashboard/admin/jobs')}
                    className="text-purple-600 hover:text-purple-800 dark:text-purple-400 dark:hover:text-purple-200 font-medium"
                  >
                    View All Jobs
                  </button>
                </div>
              </div>
              
              <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {recentJobs.slice(0, 5).map((job) => (
                  <div key={job.id} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-1">
                          <h4 className="font-medium text-gray-900 dark:text-white">{job.title}</h4>
                          {getStatusBadge(job.status)}
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400">
                          ${job.budget.toLocaleString()} • by {job.hirer.name} • {new Date(job.createdAt).toLocaleDateString()}
                        </div>
                      </div>
                      <button 
                        onClick={() => router.push(`/jobs/${job.id}`)}
                        className="p-1 text-gray-400 hover:text-purple-600 dark:hover:text-purple-400"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            
            {/* Admin Actions */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Admin Actions</h3>
              <div className="space-y-3">
                <button 
                  onClick={() => router.push('/dashboard/admin/users')}
                  className="w-full text-left p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <Users className="w-5 h-5 text-blue-600" />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Manage Users</div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">View and edit user accounts</div>
                    </div>
                  </div>
                </button>
                
                <button 
                  onClick={() => router.push('/dashboard/admin/categories')}
                  className="w-full text-left p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <FileText className="w-5 h-5 text-purple-600" />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Manage Categories</div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">Add/edit job categories</div>
                    </div>
                  </div>
                </button>
                
                <button 
                  onClick={() => router.push('/dashboard/admin/disputes')}
                  className="w-full text-left p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <Shield className="w-5 h-5 text-red-600" />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Resolve Disputes</div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">
                        {stats.urgent.disputeCount} pending
                      </div>
                    </div>
                  </div>
                </button>
                
                <button 
                  onClick={() => router.push('/dashboard/admin/analytics')}
                  className="w-full text-left p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <BarChart3 className="w-5 h-5 text-green-600" />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Analytics</div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">Platform insights</div>
                    </div>
                  </div>
                </button>
              </div>
            </div>

            {/* System Health */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">System Health</h3>
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm text-gray-600 dark:text-gray-400">User Activity</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {Math.round((stats.health.activeUsers / (stats.health.activeUsers + stats.health.inactiveUsers)) * 100)}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div 
                      className="bg-green-600 h-2 rounded-full" 
                      style={{ 
                        width: `${Math.round((stats.health.activeUsers / (stats.health.activeUsers + stats.health.inactiveUsers)) * 100)}%` 
                      }}
                    ></div>
                  </div>
                </div>
                
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Job Success Rate</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {stats.jobs.successRate.toFixed(0)}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div 
                      className="bg-blue-600 h-2 rounded-full" 
                      style={{ width: `${stats.jobs.successRate}%` }}
                    ></div>
                  </div>
                </div>
                
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Payment Health</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {Math.round((1 - (stats.health.disputedPayments / Math.max(stats.health.escrowPayments, 1))) * 100)}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div 
                      className="bg-purple-600 h-2 rounded-full" 
                      style={{ 
                        width: `${Math.round((1 - (stats.health.disputedPayments / Math.max(stats.health.escrowPayments, 1))) * 100)}%` 
                      }}
                    ></div>
                  </div>
                </div>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Quick Stats</h3>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">New users today</span>
                  <span className="font-medium text-gray-900 dark:text-white">
                    {stats.overview.userGrowth.lastDay}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">New users this week</span>
                  <span className="font-medium text-gray-900 dark:text-white">
                    {stats.overview.userGrowth.last7Days}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Average rating</span>
                  <span className="font-medium text-gray-900 dark:text-white">
                    {stats.overview.averageRating.toFixed(1)} / 5.0
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Total jobs</span>
                  <span className="font-medium text-gray-900 dark:text-white">
                    {stats.jobs.total.toLocaleString()}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Total gigs</span>
                  <span className="font-medium text-gray-900 dark:text-white">
                    {stats.gigs.total.toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}