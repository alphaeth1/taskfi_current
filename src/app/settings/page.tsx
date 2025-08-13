'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Trash2, Upload, Save, AlertTriangle, User, Wallet, Bell, Shield, Eye, EyeOff } from 'lucide-react'

interface UserProfile {
  id: string
  name: string
  username: string
  bio: string
  avatarUrl: string
  categories: string[]
  isVerified: boolean
  walletAddress: string
  walletBalance: number
  totalEarned: number
  totalSpent: number
}

interface NotificationSettings {
  emailNotifications: boolean
  pushNotifications: boolean
  jobAlerts: boolean
  paymentAlerts: boolean
  messageAlerts: boolean
}

interface PrivacySettings {
  showProfile: boolean
  showEarnings: boolean
  showReviews: boolean
  allowDirectMessages: boolean
}

export default function SettingsPage() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [activeTab, setActiveTab] = useState('profile')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [profile, setProfile] = useState<UserProfile | null>(null)
  const [notifications, setNotifications] = useState<NotificationSettings>({
    emailNotifications: true,
    pushNotifications: true,
    jobAlerts: true,
    paymentAlerts: true,
    messageAlerts: true
  })
  const [privacy, setPrivacy] = useState<PrivacySettings>({
    showProfile: true,
    showEarnings: false,
    showReviews: true,
    allowDirectMessages: true
  })

  useEffect(() => {
    if (status === 'unauthenticated') {
      router.push('/')
      return
    }
    if (session?.user) {
      fetchUserProfile()
    }
  }, [session, status])

  const fetchUserProfile = async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/users/${session?.user.id}`)
      if (response.ok) {
        const userData = await response.json()
        setProfile(userData.user)
      }
    } catch (error) {
      console.error('Failed to fetch user profile:', error)
    }
    setLoading(false)
  }

  const handleProfileUpdate = async () => {
    if (!profile) return
    setSaving(true)
    try {
      const response = await fetch(`/api/users/${profile.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: profile.name,
          username: profile.username,
          bio: profile.bio,
          categories: profile.categories
        })
      })
      if (response.ok) {
        alert('Profile updated successfully!')
      }
    } catch (error) {
      console.error('Failed to update profile:', error)
      alert('Failed to update profile')
    }
    setSaving(false)
  }

  const handleNotificationUpdate = async () => {
    setSaving(true)
    try {
      const response = await fetch('/api/users/settings/notifications', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(notifications)
      })
      if (response.ok) {
        alert('Notification settings updated!')
      }
    } catch (error) {
      console.error('Failed to update notifications:', error)
      alert('Failed to update notification settings')
    }
    setSaving(false)
  }

  const handlePrivacyUpdate = async () => {
    setSaving(true)
    try {
      const response = await fetch('/api/users/settings/privacy', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(privacy)
      })
      if (response.ok) {
        alert('Privacy settings updated!')
      }
    } catch (error) {
      console.error('Failed to update privacy:', error)
      alert('Failed to update privacy settings')
    }
    setSaving(false)
  }

  const handleAvatarUpload = async (file: File) => {
    if (!file) return
    
    const formData = new FormData()
    formData.append('avatar', file)
    
    try {
      const response = await fetch('/api/users/upload/avatar', {
        method: 'POST',
        body: formData
      })
      if (response.ok) {
        const { avatarUrl } = await response.json()
        setProfile(prev => prev ? { ...prev, avatarUrl } : null)
        alert('Avatar updated successfully!')
      }
    } catch (error) {
      console.error('Failed to upload avatar:', error)
      alert('Failed to upload avatar')
    }
  }

  const handleWithdrawFunds = async () => {
    if (!profile?.walletBalance) return
    
    try {
      const response = await fetch('/api/wallet/withdraw', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount: profile.walletBalance })
      })
      if (response.ok) {
        alert('Withdrawal successful!')
        fetchUserProfile() // Refresh balance
      }
    } catch (error) {
      console.error('Failed to withdraw:', error)
      alert('Failed to process withdrawal')
    }
  }

  const handleDeleteAccount = async () => {
    if (!showDeleteConfirm) return
    
    try {
      const response = await fetch(`/api/users/${profile?.id}`, {
        method: 'DELETE'
      })
      if (response.ok) {
        alert('Account deleted successfully')
        router.push('/')
      }
    } catch (error) {
      console.error('Failed to delete account:', error)
      alert('Failed to delete account')
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-purple-600"></div>
      </div>
    )
  }

  if (!profile) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Profile not found</h2>
          <Button onClick={() => router.push('/dashboard')}>Go to Dashboard</Button>
        </div>
      </div>
    )
  }

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'wallet', label: 'Wallet', icon: Wallet },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'privacy', label: 'Privacy', icon: Shield },
    { id: 'danger', label: 'Danger Zone', icon: AlertTriangle }
  ]

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Settings</h1>
              <p className="text-gray-600 dark:text-gray-400 mt-1">Manage your account settings and preferences</p>
            </div>
            <Button onClick={() => router.push('/dashboard')} variant="outline">
              Back to Dashboard
            </Button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex gap-8">
          {/* Sidebar */}
          <div className="w-64 space-y-2">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center gap-3 px-4 py-3 text-left rounded-lg transition-colors ${
                    activeTab === tab.id
                      ? 'bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300'
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
                >
                  <Icon className="h-5 w-5" />
                  {tab.label}
                </button>
              )
            })}
          </div>

          {/* Content */}
          <div className="flex-1">
            {activeTab === 'profile' && (
              <Card>
                <CardHeader>
                  <CardTitle>Profile Information</CardTitle>
                  <CardDescription>Update your profile information and avatar</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Avatar Upload */}
                  <div className="flex items-center gap-6">
                    <div className="relative">
                      <img
                        src={profile.avatarUrl || '/avatars/blockchain-architect.png'}
                        alt="Avatar"
                        className="w-24 h-24 rounded-full object-cover"
                      />
                      <label className="absolute bottom-0 right-0 bg-purple-600 hover:bg-purple-700 text-white p-2 rounded-full cursor-pointer transition-colors">
                        <Upload className="h-4 w-4" />
                        <input
                          type="file"
                          accept="image/*"
                          className="hidden"
                          onChange={(e) => e.target.files?.[0] && handleAvatarUpload(e.target.files[0])}
                        />
                      </label>
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900 dark:text-white">Profile Picture</h3>
                      <p className="text-sm text-gray-600 dark:text-gray-400">Upload a new profile picture</p>
                    </div>
                  </div>

                  {/* Profile Fields */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Full Name
                      </label>
                      <Input
                        value={profile.name}
                        onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                        placeholder="Enter your full name"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Username
                      </label>
                      <Input
                        value={profile.username}
                        onChange={(e) => setProfile({ ...profile, username: e.target.value })}
                        placeholder="Enter your username"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Bio
                    </label>
                    <textarea
                      value={profile.bio}
                      onChange={(e) => setProfile({ ...profile, bio: e.target.value })}
                      rows={4}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500 dark:bg-gray-700 dark:text-white"
                      placeholder="Tell us about yourself..."
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Skills/Categories
                    </label>
                    <div className="flex flex-wrap gap-2">
                      {profile.categories.map((category, index) => (
                        <span
                          key={index}
                          className="bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 px-3 py-1 rounded-full text-sm"
                        >
                          {category}
                        </span>
                      ))}
                    </div>
                  </div>

                  <Button onClick={handleProfileUpdate} disabled={saving} className="w-full">
                    <Save className="h-4 w-4 mr-2" />
                    {saving ? 'Saving...' : 'Save Changes'}
                  </Button>
                </CardContent>
              </Card>
            )}

            {activeTab === 'wallet' && (
              <Card>
                <CardHeader>
                  <CardTitle>Wallet & Earnings</CardTitle>
                  <CardDescription>Manage your wallet balance and earnings</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-gradient-to-r from-purple-500 to-pink-500 p-6 rounded-lg text-white">
                      <h3 className="text-sm font-medium opacity-80">Wallet Balance</h3>
                      <p className="text-2xl font-bold">${profile.walletBalance?.toFixed(2) || '0.00'}</p>
                    </div>
                    <div className="bg-gradient-to-r from-green-500 to-blue-500 p-6 rounded-lg text-white">
                      <h3 className="text-sm font-medium opacity-80">Total Earned</h3>
                      <p className="text-2xl font-bold">${profile.totalEarned?.toFixed(2) || '0.00'}</p>
                    </div>
                    <div className="bg-gradient-to-r from-orange-500 to-red-500 p-6 rounded-lg text-white">
                      <h3 className="text-sm font-medium opacity-80">Total Spent</h3>
                      <p className="text-2xl font-bold">${profile.totalSpent?.toFixed(2) || '0.00'}</p>
                    </div>
                  </div>

                  <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-6">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Wallet Address</h3>
                    <div className="flex items-center gap-4">
                      <code className="bg-gray-100 dark:bg-gray-800 px-3 py-2 rounded text-sm flex-1">
                        {profile.walletAddress}
                      </code>
                      <Button
                        onClick={() => navigator.clipboard.writeText(profile.walletAddress)}
                        variant="outline"
                        size="sm"
                      >
                        Copy
                      </Button>
                    </div>
                  </div>

                  {profile.walletBalance && profile.walletBalance > 0 && (
                    <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-6">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Withdraw Funds</h3>
                      <p className="text-gray-600 dark:text-gray-400 mb-4">
                        Withdraw your earnings to your connected Solana wallet
                      </p>
                      <Button onClick={handleWithdrawFunds} className="w-full">
                        Withdraw ${profile.walletBalance.toFixed(2)} to Wallet
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {activeTab === 'notifications' && (
              <Card>
                <CardHeader>
                  <CardTitle>Notification Settings</CardTitle>
                  <CardDescription>Control how you receive notifications</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {Object.entries(notifications).map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium text-gray-900 dark:text-white">
                          {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                        </h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                          Receive notifications for {key.toLowerCase().replace(/([A-Z])/g, ' $1')}
                        </p>
                      </div>
                      <button
                        onClick={() => setNotifications({ ...notifications, [key]: !value })}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          value ? 'bg-purple-600' : 'bg-gray-200 dark:bg-gray-700'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            value ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                    </div>
                  ))}
                  <Button onClick={handleNotificationUpdate} disabled={saving} className="w-full">
                    {saving ? 'Saving...' : 'Save Notification Settings'}
                  </Button>
                </CardContent>
              </Card>
            )}

            {activeTab === 'privacy' && (
              <Card>
                <CardHeader>
                  <CardTitle>Privacy Settings</CardTitle>
                  <CardDescription>Control what information is visible to others</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {Object.entries(privacy).map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {value ? <Eye className="h-5 w-5 text-green-600" /> : <EyeOff className="h-5 w-5 text-gray-400" />}
                        <div>
                          <h3 className="font-medium text-gray-900 dark:text-white">
                            {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                          </h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400">
                            {value ? 'Visible to others' : 'Hidden from others'}
                          </p>
                        </div>
                      </div>
                      <button
                        onClick={() => setPrivacy({ ...privacy, [key]: !value })}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          value ? 'bg-green-600' : 'bg-gray-200 dark:bg-gray-700'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            value ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                    </div>
                  ))}
                  <Button onClick={handlePrivacyUpdate} disabled={saving} className="w-full">
                    {saving ? 'Saving...' : 'Save Privacy Settings'}
                  </Button>
                </CardContent>
              </Card>
            )}

            {activeTab === 'danger' && (
              <Card className="border-red-200 dark:border-red-800">
                <CardHeader>
                  <CardTitle className="text-red-600 dark:text-red-400">Danger Zone</CardTitle>
                  <CardDescription>Irreversible actions that permanently affect your account</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="border border-red-200 dark:border-red-800 rounded-lg p-6 bg-red-50 dark:bg-red-950">
                    <h3 className="text-lg font-semibold text-red-900 dark:text-red-100 mb-2">
                      Delete Account
                    </h3>
                    <p className="text-red-700 dark:text-red-300 mb-4">
                      Once you delete your account, there is no going back. This will permanently delete your profile,
                      all your data, and remove you from all projects.
                    </p>
                    {!showDeleteConfirm ? (
                      <Button
                        onClick={() => setShowDeleteConfirm(true)}
                        variant="destructive"
                        className="w-full"
                      >
                        <Trash2 className="h-4 w-4 mr-2" />
                        Delete Account
                      </Button>
                    ) : (
                      <div className="space-y-4">
                        <p className="text-red-800 dark:text-red-200 font-medium">
                          Are you absolutely sure? This action cannot be undone.
                        </p>
                        <div className="flex gap-4">
                          <Button
                            onClick={handleDeleteAccount}
                            variant="destructive"
                            className="flex-1"
                          >
                            Yes, Delete My Account
                          </Button>
                          <Button
                            onClick={() => setShowDeleteConfirm(false)}
                            variant="outline"
                            className="flex-1"
                          >
                            Cancel
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}