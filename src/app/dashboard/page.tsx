'use client'

import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { useEffect } from 'react'
import { Loader2 } from 'lucide-react'

export default function DashboardRouter() {
  const { data: session, status } = useSession()
  const router = useRouter()

  useEffect(() => {
    if (status === 'loading') return

    if (!session) {
      router.push('/auth/signin?callbackUrl=/dashboard')
      return
    }

    // Route to role-specific dashboard
    switch (session.user.role) {
      case 'FREELANCER':
        router.push('/dashboard/freelancer')
        break
      case 'HIRER':
        router.push('/dashboard/hirer')
        break
      case 'ADMIN':
        router.push('/dashboard/admin')
        break
      default:
        router.push('/onboarding')
        break
    }
  }, [session, status, router])

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 to-blue-50 dark:from-purple-950 dark:to-blue-950 flex items-center justify-center">
      <div className="text-center space-y-4">
        <Loader2 className="w-8 h-8 animate-spin mx-auto text-purple-600" />
        <p className="text-gray-600 dark:text-gray-400">Loading your dashboard...</p>
      </div>
    </div>
  )
}