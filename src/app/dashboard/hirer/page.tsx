'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import {
  Briefcase,
  DollarSign,
  Users,
  Clock,
  CheckCircle,
  AlertCircle,
  Plus,
  Edit3,
  Eye,
  ChevronRight,
  Calendar,
  Star,
  MessageCircle,
  TrendingUp,
  FileText,
  Search,
} from 'lucide-react'

interface Job {
  id: string
  title: string
  budget: number
  status: 'OPEN' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED' | 'DISPUTED'
  deadline?: string
  isUrgent: boolean
  createdAt: string
  freelancer?: {
    id: string
    name: string
    username: string
    avatarUrl?: string
    rating: number
  }
  _count: {
    applications: number
  }
  category: {
    name: string
  }
}

interface Payment {
  id: string
  amount: number
  currency: string
  status: string
  createdAt: string
  job?: {
    title: string
    freelancer?: {
      name: string
    }
  }
  gig?: {
    title: string
    freelancer: {
      name: string
    }
  }
}

export default function HirerDashboard() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [loading, setLoading] = useState(true)
  const [jobs, setJobs] = useState<Job[]>([])
  const [payments, setPayments] = useState<Payment[]>([])
  const [stats, setStats] = useState({
    totalSpent: 0,
    activeJobs: 0,
    completedJobs: 0,
    pendingApplications: 0,
    escrowAmount: 0,
    successRate: 0,
  })

  useEffect(() => {
    if (status === 'loading') return

    if (!session) {
      router.push('/auth/signin?callbackUrl=/dashboard/hirer')
      return
    }

    if (session.user.role !== 'HIRER') {
      router.push('/dashboard')
      return
    }

    fetchDashboardData()
  }, [session, status, router])

  const fetchDashboardData = async () => {
    try {
      const [jobsRes, paymentsRes] = await Promise.all([
        fetch('/api/jobs'),
        fetch('/api/payments'),
      ])

      if (jobsRes.ok) {
        const jobsData = await jobsRes.json()
        setJobs(jobsData.jobs || [])
        
        // Calculate job stats
        const activeJobs = jobsData.jobs?.filter((j: Job) => j.status === 'OPEN' || j.status === 'IN_PROGRESS').length || 0
        const completedJobs = jobsData.jobs?.filter((j: Job) => j.status === 'COMPLETED').length || 0
        const totalJobs = jobsData.jobs?.length || 0
        const pendingApplications = jobsData.jobs?.reduce((sum: number, job: Job) => sum + job._count.applications, 0) || 0
        const successRate = totalJobs > 0 ? (completedJobs / totalJobs) * 100 : 0

        setStats(prev => ({
          ...prev,
          activeJobs,
          completedJobs,
          pendingApplications,
          successRate,
        }))
      }

      if (paymentsRes.ok) {
        const paymentsData = await paymentsRes.json()
        setPayments(paymentsData.payments || [])
        
        setStats(prev => ({
          ...prev,
          totalSpent: session?.user.totalSpent || 0,
          escrowAmount: paymentsData.stats?.totalInEscrow || 0,
        }))
      }
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  const getStatusBadge = (status: string) => {
    const statusStyles = {
      OPEN: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      IN_PROGRESS: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
      COMPLETED: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      CANCELLED: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200',
      DISPUTED: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
      ESCROW: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      RELEASED: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      PENDING: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
    }

    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusStyles[status as keyof typeof statusStyles] || statusStyles.CANCELLED}`}>
        {status.replace('_', ' ')}
      </span>
    )
  }

  const getUrgencyBadge = (isUrgent: boolean) => {
    if (!isUrgent) return null
    
    return (
      <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
        URGENT
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 to-blue-50 dark:from-purple-950 dark:to-blue-950">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Welcome back, {session?.user.name}
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Manage your projects, hire talented freelancers, and track your business growth
          </p>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Spent</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  ${stats.totalSpent.toLocaleString()}
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
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Jobs</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.activeJobs}</p>
              </div>
              <div className="bg-blue-100 dark:bg-blue-900 p-3 rounded-lg">
                <Briefcase className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Completed Jobs</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.completedJobs}</p>
              </div>
              <div className="bg-green-100 dark:bg-green-900 p-3 rounded-lg">
                <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Success Rate</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {stats.successRate.toFixed(0)}%
                </p>
              </div>
              <div className="bg-purple-100 dark:bg-purple-900 p-3 rounded-lg">
                <TrendingUp className="w-6 h-6 text-purple-600 dark:text-purple-400" />
              </div>
            </div>
          </div>
        </div>

        {/* Pending Applications Alert */}
        {stats.pendingApplications > 0 && (
          <div className="mb-8 bg-yellow-50 dark:bg-yellow-950 border border-yellow-200 dark:border-yellow-800 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <AlertCircle className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
                <div>
                  <h3 className="text-lg font-semibold text-yellow-900 dark:text-yellow-100">
                    Pending Applications
                  </h3>
                  <p className="text-yellow-700 dark:text-yellow-300 mt-1">
                    You have {stats.pendingApplications} applications waiting for review
                  </p>
                </div>
              </div>
              <button 
                onClick={() => router.push('/dashboard/hirer/jobs')}
                className="text-yellow-600 hover:text-yellow-800 dark:text-yellow-400 dark:hover:text-yellow-200 font-medium"
              >
                Review Applications <ChevronRight className="w-4 h-4 inline ml-1" />
              </button>
            </div>
          </div>
        )}

        {/* Escrow Balance Alert */}
        {stats.escrowAmount > 0 && (
          <div className="mb-8 bg-blue-50 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-blue-900 dark:text-blue-100">
                  Funds in Escrow
                </h3>
                <p className="text-blue-700 dark:text-blue-300 mt-1">
                  ${stats.escrowAmount.toLocaleString()} is currently held in escrow for active projects
                </p>
              </div>
              <button 
                onClick={() => router.push('/dashboard/hirer/payments')}
                className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200"
              >
                Manage Payments <ChevronRight className="w-4 h-4 inline ml-1" />
              </button>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-8">
            
            {/* Jobs Management */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-semibold text-gray-900 dark:text-white">My Jobs</h2>
                  <button 
                    onClick={() => router.push('/dashboard/hirer/jobs/create')}
                    className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Post New Job</span>
                  </button>
                </div>
              </div>
              
              <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {jobs.length === 0 ? (
                  <div className="p-6 text-center">
                    <Briefcase className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No jobs posted yet</h3>
                    <p className="text-gray-600 dark:text-gray-400 mb-4">
                      Post your first job to start finding talented freelancers
                    </p>
                    <button 
                      onClick={() => router.push('/dashboard/hirer/jobs/create')}
                      className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded-lg transition-colors"
                    >
                      Post Your First Job
                    </button>
                  </div>
                ) : (
                  jobs.slice(0, 5).map((job) => (
                    <div key={job.id} className="p-6 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <h3 className="font-medium text-gray-900 dark:text-white">{job.title}</h3>
                            {getStatusBadge(job.status)}
                            {getUrgencyBadge(job.isUrgent)}
                          </div>
                          <div className="flex items-center space-x-6 text-sm text-gray-600 dark:text-gray-400 mb-2">
                            <div className="flex items-center space-x-1">
                              <DollarSign className="w-4 h-4" />
                              <span>${job.budget.toLocaleString()}</span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <Users className="w-4 h-4" />
                              <span>{job._count.applications} applications</span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <Calendar className="w-4 h-4" />
                              <span>{new Date(job.createdAt).toLocaleDateString()}</span>
                            </div>
                            <span className="text-purple-600 dark:text-purple-400">{job.category.name}</span>
                          </div>
                          {job.freelancer && (
                            <div className="flex items-center space-x-2 text-sm">
                              <span className="text-gray-600 dark:text-gray-400">Assigned to:</span>
                              <div className="flex items-center space-x-2">
                                {job.freelancer.avatarUrl && (
                                  <img 
                                    src={job.freelancer.avatarUrl} 
                                    alt={job.freelancer.name}
                                    className="w-6 h-6 rounded-full"
                                  />
                                )}
                                <span className="font-medium text-gray-900 dark:text-white">
                                  {job.freelancer.name}
                                </span>
                                <div className="flex items-center space-x-1">
                                  <Star className="w-3 h-3 text-yellow-400 fill-current" />
                                  <span className="text-gray-600 dark:text-gray-400">
                                    {job.freelancer.rating.toFixed(1)}
                                  </span>
                                </div>
                              </div>
                            </div>
                          )}
                          {job.deadline && (
                            <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                              <Clock className="w-4 h-4 inline mr-1" />
                              Deadline: {new Date(job.deadline).toLocaleDateString()}
                            </div>
                          )}
                        </div>
                        <div className="flex items-center space-x-2 ml-4">
                          <button 
                            onClick={() => router.push(`/jobs/${job.id}`)}
                            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                            title="View job"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          {job.status === 'OPEN' && (
                            <button 
                              onClick={() => router.push(`/dashboard/hirer/jobs/${job.id}/edit`)}
                              className="p-2 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400"
                              title="Edit job"
                            >
                              <Edit3 className="w-4 h-4" />
                            </button>
                          )}
                          {job._count.applications > 0 && (
                            <button 
                              onClick={() => router.push(`/dashboard/hirer/jobs/${job.id}/applications`)}
                              className="p-2 text-gray-400 hover:text-purple-600 dark:hover:text-purple-400"
                              title="View applications"
                            >
                              <Users className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  ))
                )}
                
                {jobs.length > 5 && (
                  <div className="p-4 text-center border-t border-gray-200 dark:border-gray-700">
                    <button 
                      onClick={() => router.push('/dashboard/hirer/jobs')}
                      className="text-purple-600 hover:text-purple-800 dark:text-purple-400 dark:hover:text-purple-200 font-medium"
                    >
                      View All Jobs ({jobs.length})
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Recent Payments */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Recent Payments</h2>
                  <button 
                    onClick={() => router.push('/dashboard/hirer/payments')}
                    className="text-purple-600 hover:text-purple-800 dark:text-purple-400 dark:hover:text-purple-200 font-medium"
                  >
                    View All
                  </button>
                </div>
              </div>
              
              <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {payments.length === 0 ? (
                  <div className="p-6 text-center">
                    <DollarSign className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No payments yet</h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      Your payment history will appear here once you start hiring freelancers
                    </p>
                  </div>
                ) : (
                  payments.slice(0, 5).map((payment) => (
                    <div key={payment.id} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="font-medium text-gray-900 dark:text-white">
                            {payment.job?.title || payment.gig?.title || 'Payment'}
                          </div>
                          <div className="text-sm text-gray-600 dark:text-gray-400">
                            To: {payment.job?.freelancer?.name || payment.gig?.freelancer.name} • {new Date(payment.createdAt).toLocaleDateString()}
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="font-semibold text-gray-900 dark:text-white">
                            ${payment.amount.toLocaleString()} {payment.currency}
                          </div>
                          {getStatusBadge(payment.status)}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            
            {/* Quick Actions */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Quick Actions</h3>
              <div className="space-y-3">
                <button 
                  onClick={() => router.push('/browse/gigs')}
                  className="w-full text-left p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <Search className="w-5 h-5 text-purple-600" />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Browse Gigs</div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">Find ready-made services</div>
                    </div>
                  </div>
                </button>
                
                <button 
                  onClick={() => router.push('/dashboard/hirer/jobs/create')}
                  className="w-full text-left p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <Plus className="w-5 h-5 text-green-600" />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Post New Job</div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">Get custom proposals</div>
                    </div>
                  </div>
                </button>
                
                <button 
                  onClick={() => router.push('/dashboard/hirer/profile')}
                  className="w-full text-left p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <Edit3 className="w-5 h-5 text-blue-600" />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Edit Profile</div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">Update your information</div>
                    </div>
                  </div>
                </button>
              </div>
            </div>

            {/* Hiring Tips */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Hiring Tips</h3>
              <div className="space-y-4 text-sm">
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-purple-600 rounded-full mt-2 flex-shrink-0"></div>
                  <p className="text-gray-600 dark:text-gray-400">
                    Write clear job descriptions with specific requirements to attract qualified freelancers
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-purple-600 rounded-full mt-2 flex-shrink-0"></div>
                  <p className="text-gray-600 dark:text-gray-400">
                    Set realistic budgets and deadlines to ensure quality work
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-purple-600 rounded-full mt-2 flex-shrink-0"></div>
                  <p className="text-gray-600 dark:text-gray-400">
                    Review freelancer portfolios and ratings before hiring
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-purple-600 rounded-full mt-2 flex-shrink-0"></div>
                  <p className="text-gray-600 dark:text-gray-400">
                    Communicate clearly and provide feedback to build long-term relationships
                  </p>
                </div>
              </div>
            </div>

            {/* Platform Stats */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Your Impact</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Jobs Completed</span>
                  <span className="font-semibold text-gray-900 dark:text-white">{stats.completedJobs}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Freelancers Hired</span>
                  <span className="font-semibold text-gray-900 dark:text-white">
                    {jobs.filter(job => job.freelancer).length}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Success Rate</span>
                  <span className="font-semibold text-gray-900 dark:text-white">{stats.successRate.toFixed(0)}%</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Total Investment</span>
                  <span className="font-semibold text-gray-900 dark:text-white">
                    ${stats.totalSpent.toLocaleString()}
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