'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import {
  Briefcase,
  DollarSign,
  Star,
  TrendingUp,
  Eye,
  MessageCircle,
  Calendar,
  Clock,
  Award,
  Plus,
  Edit3,
  Trash2,
  ExternalLink,
  ChevronRight,
  Filter,
  Search,
} from 'lucide-react'

interface Gig {
  id: string
  title: string
  status: 'ACTIVE' | 'PAUSED' | 'INACTIVE'
  rating: number
  orderCount: number
  viewCount: number
  packages: any[]
  minPrice: number
  maxPrice: number
  createdAt: string
  gallery: string[]
}

interface JobApplication {
  id: string
  isAccepted: boolean | null
  proposedBudget: number
  estimatedDays: number
  createdAt: string
  job: {
    id: string
    title: string
    budget: number
    status: string
    hirer: {
      name: string
      username: string
      avatarUrl?: string
    }
  }
}

interface Payment {
  id: string
  amount: number
  currency: string
  status: string
  createdAt: string
  gig?: {
    title: string
  }
  job?: {
    title: string
  }
}

export default function FreelancerDashboard() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [loading, setLoading] = useState(true)
  const [gigs, setGigs] = useState<Gig[]>([])
  const [applications, setApplications] = useState<JobApplication[]>([])
  const [payments, setPayments] = useState<Payment[]>([])
  const [stats, setStats] = useState({
    totalEarnings: 0,
    activeGigs: 0,
    completedJobs: 0,
    rating: 0,
    pendingApplications: 0,
    escrowBalance: 0,
  })

  useEffect(() => {
    if (status === 'loading') return

    if (!session) {
      router.push('/auth/signin?callbackUrl=/dashboard/freelancer')
      return
    }

    if (session.user.role !== 'FREELANCER') {
      router.push('/dashboard')
      return
    }

    fetchDashboardData()
  }, [session, status, router])

  const fetchDashboardData = async () => {
    try {
      const [gigsRes, paymentsRes] = await Promise.all([
        fetch('/api/gigs?freelancer=' + session?.user.id),
        fetch('/api/payments'),
      ])

      if (gigsRes.ok) {
        const gigsData = await gigsRes.json()
        setGigs(gigsData.gigs || [])
      }

      if (paymentsRes.ok) {
        const paymentsData = await paymentsRes.json()
        setPayments(paymentsData.payments || [])
        
        // Calculate stats
        setStats({
          totalEarnings: session?.user.totalEarned || 0,
          activeGigs: gigsData.gigs?.filter((g: Gig) => g.status === 'ACTIVE').length || 0,
          completedJobs: session?.user.completedJobs || 0,
          rating: session?.user.rating || 0,
          pendingApplications: 0, // Will be updated when we fetch applications
          escrowBalance: paymentsData.stats?.totalInEscrow || 0,
        })
      }
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  const getStatusBadge = (status: string) => {
    const statusStyles = {
      ACTIVE: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      PAUSED: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
      INACTIVE: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200',
      ESCROW: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      RELEASED: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      PENDING: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
    }

    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusStyles[status as keyof typeof statusStyles] || statusStyles.INACTIVE}`}>
        {status}
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
            Manage your gigs, track earnings, and grow your freelance business
          </p>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Earnings</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  ${stats.totalEarnings.toLocaleString()}
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
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Gigs</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.activeGigs}</p>
              </div>
              <div className="bg-purple-100 dark:bg-purple-900 p-3 rounded-lg">
                <Briefcase className="w-6 h-6 text-purple-600 dark:text-purple-400" />
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Completed Jobs</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.completedJobs}</p>
              </div>
              <div className="bg-blue-100 dark:bg-blue-900 p-3 rounded-lg">
                <Award className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Rating</p>
                <div className="flex items-center space-x-2">
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.rating.toFixed(1)}
                  </p>
                  <Star className="w-5 h-5 text-yellow-400 fill-current" />
                </div>
              </div>
              <div className="bg-yellow-100 dark:bg-yellow-900 p-3 rounded-lg">
                <TrendingUp className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
              </div>
            </div>
          </div>
        </div>

        {/* Escrow Balance Alert */}
        {stats.escrowBalance > 0 && (
          <div className="mb-8 bg-blue-50 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-blue-900 dark:text-blue-100">
                  Funds in Escrow
                </h3>
                <p className="text-blue-700 dark:text-blue-300 mt-1">
                  You have ${stats.escrowBalance.toLocaleString()} waiting to be released upon job completion
                </p>
              </div>
              <button 
                onClick={() => router.push('/dashboard/freelancer/payments')}
                className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200"
              >
                View Details <ChevronRight className="w-4 h-4 inline ml-1" />
              </button>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-8">
            
            {/* Gigs Management */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-semibold text-gray-900 dark:text-white">My Gigs</h2>
                  <button 
                    onClick={() => router.push('/dashboard/freelancer/gigs/create')}
                    className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Create Gig</span>
                  </button>
                </div>
              </div>
              
              <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {gigs.length === 0 ? (
                  <div className="p-6 text-center">
                    <Briefcase className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No gigs yet</h3>
                    <p className="text-gray-600 dark:text-gray-400 mb-4">
                      Create your first gig to start earning on the platform
                    </p>
                    <button 
                      onClick={() => router.push('/dashboard/freelancer/gigs/create')}
                      className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded-lg transition-colors"
                    >
                      Create Your First Gig
                    </button>
                  </div>
                ) : (
                  gigs.slice(0, 5).map((gig) => (
                    <div key={gig.id} className="p-6 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <h3 className="font-medium text-gray-900 dark:text-white">{gig.title}</h3>
                            {getStatusBadge(gig.status)}
                          </div>
                          <div className="flex items-center space-x-6 text-sm text-gray-600 dark:text-gray-400">
                            <div className="flex items-center space-x-1">
                              <DollarSign className="w-4 h-4" />
                              <span>${gig.minPrice} - ${gig.maxPrice}</span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <Eye className="w-4 h-4" />
                              <span>{gig.viewCount} views</span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <Star className="w-4 h-4" />
                              <span>{gig.rating.toFixed(1)}</span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <Calendar className="w-4 h-4" />
                              <span>{gig.orderCount} orders</span>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2 ml-4">
                          <button 
                            onClick={() => router.push(`/gigs/${gig.id}`)}
                            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                            title="View gig"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </button>
                          <button 
                            onClick={() => router.push(`/dashboard/freelancer/gigs/${gig.id}/edit`)}
                            className="p-2 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400"
                            title="Edit gig"
                          >
                            <Edit3 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
                
                {gigs.length > 5 && (
                  <div className="p-4 text-center border-t border-gray-200 dark:border-gray-700">
                    <button 
                      onClick={() => router.push('/dashboard/freelancer/gigs')}
                      className="text-purple-600 hover:text-purple-800 dark:text-purple-400 dark:hover:text-purple-200 font-medium"
                    >
                      View All Gigs ({gigs.length})
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
                    onClick={() => router.push('/dashboard/freelancer/payments')}
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
                      Your payment history will appear here once you start completing jobs
                    </p>
                  </div>
                ) : (
                  payments.slice(0, 5).map((payment) => (
                    <div key={payment.id} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="font-medium text-gray-900 dark:text-white">
                            {payment.gig?.title || payment.job?.title || 'Payment'}
                          </div>
                          <div className="text-sm text-gray-600 dark:text-gray-400">
                            {new Date(payment.createdAt).toLocaleDateString()}
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
                  onClick={() => router.push('/browse/jobs')}
                  className="w-full text-left p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <Search className="w-5 h-5 text-purple-600" />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Browse Jobs</div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">Find new opportunities</div>
                    </div>
                  </div>
                </button>
                
                <button 
                  onClick={() => router.push('/dashboard/freelancer/gigs/create')}
                  className="w-full text-left p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <Plus className="w-5 h-5 text-green-600" />
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">Create New Gig</div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">Offer your services</div>
                    </div>
                  </div>
                </button>
                
                <button 
                  onClick={() => router.push('/dashboard/freelancer/profile')}
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

            {/* Performance Insights */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Performance Insights</h3>
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Profile Completion</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">85%</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div className="bg-purple-600 h-2 rounded-full" style={{ width: '85%' }}></div>
                  </div>
                </div>
                
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Response Rate</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">92%</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div className="bg-green-600 h-2 rounded-full" style={{ width: '92%' }}></div>
                  </div>
                </div>
                
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm text-gray-600 dark:text-gray-400">On-time Delivery</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">98%</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div className="bg-blue-600 h-2 rounded-full" style={{ width: '98%' }}></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}