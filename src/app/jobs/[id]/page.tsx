'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter, useParams } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Clock, DollarSign, MapPin, User, Zap, Star, Eye, Users, Calendar, CheckCircle, AlertCircle } from 'lucide-react'

interface Job {
  id: string
  title: string
  description: string
  requirements: string[]
  budget: number
  deadline: string
  status: string
  isUrgent: boolean
  attachments: string[]
  tags: string[]
  viewCount: number
  applicantCount: number
  hirer: {
    id: string
    name: string
    username: string
    avatarUrl: string
    rating: number
    isVerified: boolean
    totalSpent: number
  }
  category: {
    id: string
    name: string
    icon: string
  }
  createdAt: string
  applications?: {
    id: string
    coverLetter: string
    proposedBudget: number
    estimatedDays: number
    isAccepted: boolean
    freelancer: {
      id: string
      name: string
      username: string
      avatarUrl: string
      rating: number
      isVerified: boolean
    }
    createdAt: string
  }[]
}

export default function JobDetailPage() {
  const { data: session } = useSession()
  const router = useRouter()
  const params = useParams()
  const jobId = params.id as string
  
  const [job, setJob] = useState<Job | null>(null)
  const [loading, setLoading] = useState(true)
  const [applying, setApplying] = useState(false)
  const [hasApplied, setHasApplied] = useState(false)
  const [showApplicationForm, setShowApplicationForm] = useState(false)
  
  const [applicationData, setApplicationData] = useState({
    coverLetter: '',
    proposedBudget: '',
    estimatedDays: ''
  })

  useEffect(() => {
    if (jobId) {
      fetchJobDetails()
      trackView()
    }
  }, [jobId])

  const fetchJobDetails = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/jobs/${jobId}`)
      if (response.ok) {
        const data = await response.json()
        setJob(data.job)
        
        // Check if user has already applied
        if (session?.user && data.job.applications) {
          const userApplication = data.job.applications.find(
            (app: any) => app.freelancer.id === session.user.id
          )
          setHasApplied(!!userApplication)
        }
      } else {
        router.push('/browse/jobs')
      }
    } catch (error) {
      console.error('Failed to fetch job details:', error)
      router.push('/browse/jobs')
    }
    setLoading(false)
  }

  const trackView = async () => {
    try {
      await fetch(`/api/jobs/${jobId}/view`, {
        method: 'POST'
      })
    } catch (error) {
      console.error('Failed to track view:', error)
    }
  }

  const handleSubmitApplication = async () => {
    if (!applicationData.coverLetter || !applicationData.proposedBudget || !applicationData.estimatedDays) {
      alert('Please fill in all fields')
      return
    }

    setApplying(true)
    try {
      const response = await fetch(`/api/jobs/${jobId}/applications`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          coverLetter: applicationData.coverLetter,
          proposedBudget: parseFloat(applicationData.proposedBudget),
          estimatedDays: parseInt(applicationData.estimatedDays)
        })
      })

      if (response.ok) {
        alert('Application submitted successfully!')
        setHasApplied(true)
        setShowApplicationForm(false)
        fetchJobDetails() // Refresh to show updated application count
      } else {
        const error = await response.json()
        alert(error.error || 'Failed to submit application')
      }
    } catch (error) {
      console.error('Failed to submit application:', error)
      alert('Failed to submit application')
    }
    setApplying(false)
  }

  const timeAgo = (date: string) => {
    const now = new Date()
    const posted = new Date(date)
    const diffInHours = Math.floor((now.getTime() - posted.getTime()) / (1000 * 60 * 60))
    
    if (diffInHours < 1) return 'Just posted'
    if (diffInHours < 24) return `${diffInHours}h ago`
    const diffInDays = Math.floor(diffInHours / 24)
    if (diffInDays < 7) return `${diffInDays}d ago`
    return `${Math.floor(diffInDays / 7)}w ago`
  }

  const formatDeadline = (deadline: string) => {
    const date = new Date(deadline)
    const now = new Date()
    const diffInDays = Math.ceil((date.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
    
    if (diffInDays < 0) return 'Overdue'
    if (diffInDays === 0) return 'Due today'
    if (diffInDays === 1) return 'Due tomorrow'
    if (diffInDays < 7) return `Due in ${diffInDays} days`
    return date.toLocaleDateString()
  }

  const renderStars = (rating: number) => {
    return Array.from({ length: 5 }, (_, i) => (
      <Star
        key={i}
        className={`h-4 w-4 ${
          i < Math.floor(rating)
            ? 'text-yellow-400 fill-current'
            : 'text-gray-300 dark:text-gray-600'
        }`}
      />
    ))
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-purple-600"></div>
      </div>
    )
  }

  if (!job) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Job not found</h2>
          <Button onClick={() => router.push('/browse/jobs')}>Browse Jobs</Button>
        </div>
      </div>
    )
  }

  const canApply = session?.user?.role === 'FREELANCER' && !hasApplied && job.status === 'OPEN'
  const isHirer = session?.user?.id === job.hirer.id

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <Button onClick={() => router.push('/browse/jobs')} variant="outline">
              ← Back to Jobs
            </Button>
            <div className="flex gap-4">
              {isHirer && (
                <Button onClick={() => router.push(`/jobs/${job.id}/manage`)}>
                  Manage Job
                </Button>
              )}
              <Button onClick={() => router.push('/dashboard')}>
                Dashboard
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-6">
            {/* Job Header */}
            <Card>
              <CardContent className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                        {job.title}
                      </h1>
                      {job.isUrgent && (
                        <span className="bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200 px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1">
                          <Zap className="h-4 w-4" />
                          Urgent
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400 mb-4">
                      <div className="flex items-center gap-1">
                        <Calendar className="h-4 w-4" />
                        Posted {timeAgo(job.createdAt)}
                      </div>
                      <div className="flex items-center gap-1">
                        <Eye className="h-4 w-4" />
                        {job.viewCount} views
                      </div>
                      <div className="flex items-center gap-1">
                        <Users className="h-4 w-4" />
                        {job.applicantCount} proposals
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <span className="bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 px-3 py-1 rounded-full text-sm">
                        {job.category.icon} {job.category.name}
                      </span>
                      {job.tags.map((tag, index) => (
                        <span
                          key={index}
                          className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-3 py-1 rounded-full text-sm"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="text-right ml-6">
                    <div className="text-3xl font-bold text-green-600 dark:text-green-400">
                      ${job.budget.toLocaleString()}
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      Fixed Price
                    </div>
                    {job.deadline && (
                      <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                        {formatDeadline(job.deadline)}
                      </div>
                    )}
                  </div>
                </div>

                {/* Status Badge */}
                <div className="flex items-center gap-2 mb-4">
                  {job.status === 'OPEN' && (
                    <span className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1">
                      <CheckCircle className="h-4 w-4" />
                      Open for proposals
                    </span>
                  )}
                  {job.status === 'IN_PROGRESS' && (
                    <span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1">
                      <Clock className="h-4 w-4" />
                      In Progress
                    </span>
                  )}
                  {job.status === 'COMPLETED' && (
                    <span className="bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1">
                      <CheckCircle className="h-4 w-4" />
                      Completed
                    </span>
                  )}
                  {hasApplied && (
                    <span className="bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200 px-3 py-1 rounded-full text-sm font-medium">
                      Applied
                    </span>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Job Description */}
            <Card>
              <CardHeader>
                <CardTitle>Job Description</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="prose dark:prose-invert max-w-none">
                  <p className="text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                    {job.description}
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Requirements */}
            <Card>
              <CardHeader>
                <CardTitle>Requirements</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2">
                  {job.requirements.map((requirement, index) => (
                    <li key={index} className="flex items-start gap-2">
                      <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-700 dark:text-gray-300">{requirement}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>

            {/* Attachments */}
            {job.attachments.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Attachments</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {job.attachments.map((attachment, index) => (
                      <a
                        key={index}
                        href={attachment}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-purple-600 dark:text-purple-400 hover:underline"
                      >
                        <span>📎</span>
                        Attachment {index + 1}
                      </a>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Application Form */}
            {canApply && showApplicationForm && (
              <Card>
                <CardHeader>
                  <CardTitle>Submit Proposal</CardTitle>
                  <CardDescription>Tell the client why you're the best fit for this project</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Cover Letter
                    </label>
                    <textarea
                      value={applicationData.coverLetter}
                      onChange={(e) => setApplicationData({ ...applicationData, coverLetter: e.target.value })}
                      rows={6}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500 dark:bg-gray-700 dark:text-white"
                      placeholder="Describe your experience and approach to this project..."
                    />
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Proposed Budget ($)
                      </label>
                      <input
                        type="number"
                        value={applicationData.proposedBudget}
                        onChange={(e) => setApplicationData({ ...applicationData, proposedBudget: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500 dark:bg-gray-700 dark:text-white"
                        placeholder="0"
                        max={job.budget}
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Estimated Days
                      </label>
                      <input
                        type="number"
                        value={applicationData.estimatedDays}
                        onChange={(e) => setApplicationData({ ...applicationData, estimatedDays: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500 dark:bg-gray-700 dark:text-white"
                        placeholder="0"
                      />
                    </div>
                  </div>
                  <div className="flex gap-4">
                    <Button
                      onClick={handleSubmitApplication}
                      disabled={applying}
                      className="flex-1"
                    >
                      {applying ? 'Submitting...' : 'Submit Proposal'}
                    </Button>
                    <Button
                      onClick={() => setShowApplicationForm(false)}
                      variant="outline"
                    >
                      Cancel
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Action Card */}
            <Card>
              <CardContent className="p-6">
                {canApply && !showApplicationForm && (
                  <Button
                    onClick={() => setShowApplicationForm(true)}
                    className="w-full mb-4"
                    size="lg"
                  >
                    Apply for this Job
                  </Button>
                )}
                {hasApplied && (
                  <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 mb-4">
                    <div className="flex items-center gap-2 text-yellow-800 dark:text-yellow-200">
                      <CheckCircle className="h-5 w-5" />
                      <span className="font-medium">Application Submitted</span>
                    </div>
                    <p className="text-yellow-700 dark:text-yellow-300 text-sm mt-1">
                      Your proposal is under review
                    </p>
                  </div>
                )}
                {!session?.user && (
                  <Button
                    onClick={() => router.push('/')}
                    className="w-full mb-4"
                    size="lg"
                  >
                    Sign In to Apply
                  </Button>
                )}
                {session?.user?.role === 'HIRER' && session.user.id !== job.hirer.id && (
                  <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-4">
                    <p className="text-blue-800 dark:text-blue-200 text-sm">
                      You're signed in as a hirer. Only freelancers can apply to jobs.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Client Info */}
            <Card>
              <CardHeader>
                <CardTitle>About the Client</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-3">
                  <img
                    src={job.hirer.avatarUrl || '/avatars/blockchain-architect.png'}
                    alt={job.hirer.name}
                    className="w-12 h-12 rounded-full object-cover"
                  />
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="font-medium text-gray-900 dark:text-white">
                        {job.hirer.name}
                      </h4>
                      {job.hirer.isVerified && (
                        <span className="text-blue-500">✓</span>
                      )}
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      @{job.hirer.username}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  {renderStars(job.hirer.rating)}
                  <span className="text-sm text-gray-500 ml-1">
                    ({job.hirer.rating.toFixed(1)})
                  </span>
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  <p>Total Spent: ${job.hirer.totalSpent?.toLocaleString() || '0'}</p>
                </div>
              </CardContent>
            </Card>

            {/* Job Stats */}
            <Card>
              <CardHeader>
                <CardTitle>Job Statistics</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Budget</span>
                  <span className="font-semibold text-green-600 dark:text-green-400">
                    ${job.budget.toLocaleString()}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Proposals</span>
                  <span className="font-semibold">{job.applicantCount}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Views</span>
                  <span className="font-semibold">{job.viewCount}</span>
                </div>
                {job.deadline && (
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Deadline</span>
                    <span className="font-semibold">{formatDeadline(job.deadline)}</span>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}