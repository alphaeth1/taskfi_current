'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Zap, User, Briefcase, Code, Palette, Shield, Star } from 'lucide-react'
import { cn, generateUsername, debounce } from '@/lib/utils'

const WEB3_CATEGORIES = [
  { id: 'smart-contract', name: 'Smart Contract Development', icon: Code },
  { id: 'defi', name: 'DeFi Development', icon: Zap },
  { id: 'nft', name: 'NFT Development', icon: Palette },
  { id: 'web3-frontend', name: 'Web3 Frontend', icon: User },
  { id: 'tokenomics', name: 'Tokenomics', icon: Star },
  { id: 'blockchain-architecture', name: 'Blockchain Architecture', icon: Shield },
  { id: 'dao', name: 'DAO Development', icon: Briefcase },
  { id: 'gamefi', name: 'GameFi Development', icon: Zap },
  { id: 'security', name: 'Web3 Security', icon: Shield },
  { id: 'metaverse', name: 'Metaverse Development', icon: User },
]

const AVATARS = [
  '/avatars/blockchain-architect.png',
  '/avatars/crypto-artist.png',
  '/avatars/cyberpunk-dev.png',
  '/avatars/dao-governance.png',
  '/avatars/defi-trader.png',
  '/avatars/gamefi-designer.png',
  '/avatars/metaverse-dev.png',
  '/avatars/nft-creator.png',
  '/avatars/rpc-engineer.png',
  '/avatars/smart-contract-dev.png',
  '/avatars/solana-validator.png',
  '/avatars/tokenomics-expert.png',
  '/avatars/web3-marketing.png',
  '/avatars/web3-security.png',
  '/avatars/web3-ui-designer.png',
]

export default function OnboardingPage() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [step, setStep] = useState(1)
  const [loading, setLoading] = useState(false)
  const [usernameAvailable, setUsernameAvailable] = useState<boolean | null>(null)
  const [checkingUsername, setCheckingUsername] = useState(false)
  
  const [formData, setFormData] = useState({
    name: '',
    username: '',
    bio: '',
    role: '' as 'FREELANCER' | 'HIRER' | '',
    categories: [] as string[],
    avatarUrl: '',
  })

  const [errors, setErrors] = useState<Record<string, string>>({})

  useEffect(() => {
    if (status === 'loading') return
    if (!session || session.user.id !== 'new-user') {
      router.push('/')
    }
  }, [session, status, router])

  const checkUsername = debounce(async (username: string) => {
    if (username.length < 3) {
      setUsernameAvailable(null)
      return
    }

    setCheckingUsername(true)
    try {
      const response = await fetch('/api/users/check-username', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      })
      const data = await response.json()
      setUsernameAvailable(data.available)
    } catch (error) {
      console.error('Username check error:', error)
    } finally {
      setCheckingUsername(false)
    }
  }, 500)

  useEffect(() => {
    if (formData.username) {
      checkUsername(formData.username)
    }
  }, [formData.username])

  useEffect(() => {
    if (formData.name && !formData.username) {
      setFormData(prev => ({ ...prev, username: generateUsername(prev.name) }))
    }
  }, [formData.name, formData.username])

  const validateStep = (stepNumber: number): boolean => {
    const newErrors: Record<string, string> = {}

    if (stepNumber === 1) {
      if (!formData.name.trim()) newErrors.name = 'Name is required'
      if (!formData.username.trim()) newErrors.username = 'Username is required'
      if (formData.username.length < 3) newErrors.username = 'Username must be at least 3 characters'
      if (!/^[a-zA-Z0-9_]+$/.test(formData.username)) newErrors.username = 'Username can only contain letters, numbers, and underscores'
      if (usernameAvailable === false) newErrors.username = 'Username is already taken'
      if (!formData.role) newErrors.role = 'Please select a role'
    }

    if (stepNumber === 2 && formData.role === 'FREELANCER') {
      if (formData.categories.length === 0) newErrors.categories = 'Please select at least one category'
      if (!formData.avatarUrl) newErrors.avatarUrl = 'Please select an avatar'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleNext = () => {
    if (validateStep(step)) {
      if (step === 1 && formData.role === 'HIRER') {
        handleSubmit() // Skip step 2 for hirers
      } else {
        setStep(step + 1)
      }
    }
  }

  const handleSubmit = async () => {
    if (!validateStep(step)) return

    setLoading(true)
    try {
      const response = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...formData,
          walletAddress: session?.user.walletAddress,
        }),
      })

      if (response.ok) {
        // Refresh session and redirect to dashboard
        window.location.href = formData.role === 'FREELANCER' ? '/freelancer' : '/hirer'
      } else {
        const error = await response.json()
        setErrors({ submit: error.error || 'Failed to create account' })
      }
    } catch (error) {
      setErrors({ submit: 'Network error. Please try again.' })
    } finally {
      setLoading(false)
    }
  }

  const toggleCategory = (categoryId: string) => {
    setFormData(prev => ({
      ...prev,
      categories: prev.categories.includes(categoryId)
        ? prev.categories.filter(id => id !== categoryId)
        : prev.categories.length < 3
        ? [...prev.categories, categoryId]
        : prev.categories
    }))
  }

  if (status === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background to-background/80 flex items-center justify-center p-4">
      <Card className="w-full max-w-2xl web3-card">
        <CardHeader className="text-center">
          <div className="flex items-center justify-center space-x-2 mb-4">
            <div className="w-8 h-8 bg-gradient-primary rounded-lg flex items-center justify-center">
              <Zap className="h-5 w-5 text-white" />
            </div>
            <span className="text-xl font-bold gradient-text">TaskFi</span>
          </div>
          <CardTitle className="text-2xl">Welcome to TaskFi</CardTitle>
          <CardDescription>
            {step === 1 ? 'Tell us about yourself' : 'Choose your expertise'}
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Step 1: Basic Info */}
          {step === 1 && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Full Name</label>
                <Input
                  placeholder="Enter your full name"
                  value={formData.name}
                  onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                  error={errors.name}
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Username</label>
                <Input
                  placeholder="Choose a unique username"
                  value={formData.username}
                  onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
                  error={errors.username}
                />
                {checkingUsername && (
                  <p className="text-xs text-muted-foreground mt-1">Checking availability...</p>
                )}
                {usernameAvailable === true && (
                  <p className="text-xs text-green-600 mt-1">Username is available!</p>
                )}
                {usernameAvailable === false && (
                  <p className="text-xs text-red-600 mt-1">Username is already taken</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Bio (Optional)</label>
                <textarea
                  className="w-full min-h-[80px] px-3 py-2 border border-input rounded-md bg-transparent text-sm resize-none focus:outline-none focus:ring-1 focus:ring-ring"
                  placeholder="Tell us about yourself..."
                  value={formData.bio}
                  onChange={(e) => setFormData(prev => ({ ...prev, bio: e.target.value }))}
                  maxLength={500}
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {formData.bio.length}/500 characters
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">I am a...</label>
                <div className="grid grid-cols-2 gap-4">
                  <button
                    type="button"
                    onClick={() => setFormData(prev => ({ ...prev, role: 'FREELANCER' }))}
                    className={cn(
                      'p-4 rounded-lg border-2 transition-all text-left',
                      formData.role === 'FREELANCER'
                        ? 'border-primary bg-primary/10'
                        : 'border-border hover:border-primary/50'
                    )}
                  >
                    <Code className="h-6 w-6 mb-2 text-primary" />
                    <h3 className="font-medium">Freelancer</h3>
                    <p className="text-sm text-muted-foreground">I want to offer my Web3 services</p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setFormData(prev => ({ ...prev, role: 'HIRER' }))}
                    className={cn(
                      'p-4 rounded-lg border-2 transition-all text-left',
                      formData.role === 'HIRER'
                        ? 'border-primary bg-primary/10'
                        : 'border-border hover:border-primary/50'
                    )}
                  >
                    <Briefcase className="h-6 w-6 mb-2 text-secondary" />
                    <h3 className="font-medium">Hirer</h3>
                    <p className="text-sm text-muted-foreground">I want to hire Web3 talent</p>
                  </button>
                </div>
                {errors.role && <p className="text-xs text-destructive mt-1">{errors.role}</p>}
              </div>
            </div>
          )}

          {/* Step 2: Categories and Avatar (Freelancers only) */}
          {step === 2 && formData.role === 'FREELANCER' && (
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium mb-2">
                  Select your expertise (up to 3)
                </label>
                <div className="grid grid-cols-2 gap-3">
                  {WEB3_CATEGORIES.map((category) => {
                    const Icon = category.icon
                    const isSelected = formData.categories.includes(category.id)
                    return (
                      <button
                        key={category.id}
                        type="button"
                        onClick={() => toggleCategory(category.id)}
                        disabled={!isSelected && formData.categories.length >= 3}
                        className={cn(
                          'p-3 rounded-lg border-2 transition-all text-left text-sm',
                          isSelected
                            ? 'border-primary bg-primary/10'
                            : 'border-border hover:border-primary/50',
                          !isSelected && formData.categories.length >= 3 && 'opacity-50 cursor-not-allowed'
                        )}
                      >
                        <Icon className="h-4 w-4 mb-1 text-primary" />
                        <div className="font-medium">{category.name}</div>
                      </button>
                    )
                  })}
                </div>
                {errors.categories && <p className="text-xs text-destructive mt-1">{errors.categories}</p>}
                <p className="text-xs text-muted-foreground mt-2">
                  Selected: {formData.categories.length}/3
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Choose your avatar</label>
                <div className="grid grid-cols-5 gap-3">
                  {AVATARS.map((avatar, index) => (
                    <button
                      key={index}
                      type="button"
                      onClick={() => setFormData(prev => ({ ...prev, avatarUrl: avatar }))}
                      className={cn(
                        'aspect-square rounded-lg border-2 overflow-hidden transition-all',
                        formData.avatarUrl === avatar
                          ? 'border-primary scale-105'
                          : 'border-border hover:border-primary/50'
                      )}
                    >
                      <img
                        src={avatar}
                        alt={`Avatar ${index + 1}`}
                        className="w-full h-full object-cover"
                      />
                    </button>
                  ))}
                </div>
                {errors.avatarUrl && <p className="text-xs text-destructive mt-1">{errors.avatarUrl}</p>}
              </div>
            </div>
          )}

          {errors.submit && (
            <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
              <p className="text-sm text-destructive">{errors.submit}</p>
            </div>
          )}

          <div className="flex justify-between pt-4">
            {step > 1 && (
              <Button
                variant="outline"
                onClick={() => setStep(step - 1)}
                disabled={loading}
              >
                Back
              </Button>
            )}
            
            <Button
              onClick={step === 2 || formData.role === 'HIRER' ? handleSubmit : handleNext}
              loading={loading}
              variant="gradient"
              className="ml-auto"
            >
              {loading ? 'Creating Account...' : 
               step === 2 || formData.role === 'HIRER' ? 'Complete Setup' : 'Next'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}