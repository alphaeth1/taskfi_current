'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Search, Filter, Star, Eye, ShoppingCart, Clock, User, Zap, Award } from 'lucide-react'

interface GigPackage {
  name: string
  description: string
  price: number
  deliveryTime: number
  revisions: number
  features: string[]
}

interface Gig {
  id: string
  title: string
  description: string
  deliverables: string[]
  packages: GigPackage[]
  gallery: string[]
  tags: string[]
  status: string
  viewCount: number
  orderCount: number
  rating: number
  freelancer: {
    id: string
    name: string
    username: string
    avatarUrl: string
    rating: number
    isVerified: boolean
    totalEarned: number
  }
  category: {
    id: string
    name: string
    icon: string
  }
  createdAt: string
}

interface Category {
  id: string
  name: string
  icon: string
}

export default function BrowseGigsPage() {
  const { data: session } = useSession()
  const router = useRouter()
  const [gigs, setGigs] = useState<Gig[]>([])
  const [categories, setCategories] = useState<Category[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('')
  const [priceMin, setPriceMin] = useState('')
  const [priceMax, setPriceMax] = useState('')
  const [sortBy, setSortBy] = useState('popular')
  const [deliveryTime, setDeliveryTime] = useState('')

  useEffect(() => {
    fetchGigs()
    fetchCategories()
  }, [searchTerm, selectedCategory, priceMin, priceMax, sortBy, deliveryTime])

  const fetchGigs = async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({
        search: searchTerm,
        category: selectedCategory,
        priceMin: priceMin,
        priceMax: priceMax,
        sortBy: sortBy,
        deliveryTime: deliveryTime,
        status: 'ACTIVE'
      })
      
      const response = await fetch(`/api/gigs?${params}`)
      if (response.ok) {
        const data = await response.json()
        setGigs(data.gigs || [])
      }
    } catch (error) {
      console.error('Failed to fetch gigs:', error)
    }
    setLoading(false)
  }

  const fetchCategories = async () => {
    try {
      const response = await fetch('/api/categories')
      if (response.ok) {
        const data = await response.json()
        setCategories(data.categories || [])
      }
    } catch (error) {
      console.error('Failed to fetch categories:', error)
    }
  }

  const handlePurchaseGig = async (gigId: string, packageIndex: number = 0) => {
    if (!session?.user) {
      router.push('/')
      return
    }

    if (session.user.role !== 'HIRER') {
      alert('Only hirers can purchase gigs')
      return
    }

    router.push(`/gigs/${gigId}/purchase?package=${packageIndex}`)
  }

  const getStartingPrice = (packages: GigPackage[]) => {
    return Math.min(...packages.map(pkg => pkg.price))
  }

  const getFastestDelivery = (packages: GigPackage[]) => {
    return Math.min(...packages.map(pkg => pkg.deliveryTime))
  }

  const clearFilters = () => {
    setSearchTerm('')
    setSelectedCategory('')
    setPriceMin('')
    setPriceMax('')
    setDeliveryTime('')
    setSortBy('popular')
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

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Browse Gigs</h1>
              <p className="text-gray-600 dark:text-gray-400 mt-1">
                Discover professional Web3 services • {gigs.length} gigs available
              </p>
            </div>
            <div className="flex gap-4">
              <Button onClick={() => router.push('/browse/jobs')} variant="outline">
                Browse Jobs
              </Button>
              <Button onClick={() => router.push('/dashboard')}>
                Dashboard
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex gap-8">
          {/* Filters Sidebar */}
          <div className="w-80 space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Filter className="h-5 w-5" />
                  Filters
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Search */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Search Gigs
                  </label>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                    <Input
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      placeholder="Search by title, skills..."
                      className="pl-10"
                    />
                  </div>
                </div>

                {/* Category */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Category
                  </label>
                  <select
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500 dark:bg-gray-700 dark:text-white"
                  >
                    <option value="">All Categories</option>
                    {categories.map((category) => (
                      <option key={category.id} value={category.id}>
                        {category.icon} {category.name}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Price Range */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Price Range
                  </label>
                  <div className="flex gap-2">
                    <Input
                      type="number"
                      value={priceMin}
                      onChange={(e) => setPriceMin(e.target.value)}
                      placeholder="Min"
                    />
                    <Input
                      type="number"
                      value={priceMax}
                      onChange={(e) => setPriceMax(e.target.value)}
                      placeholder="Max"
                    />
                  </div>
                </div>

                {/* Delivery Time */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Delivery Time
                  </label>
                  <select
                    value={deliveryTime}
                    onChange={(e) => setDeliveryTime(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500 dark:bg-gray-700 dark:text-white"
                  >
                    <option value="">Any Time</option>
                    <option value="1">1 Day</option>
                    <option value="3">3 Days</option>
                    <option value="7">1 Week</option>
                    <option value="14">2 Weeks</option>
                    <option value="30">1 Month</option>
                  </select>
                </div>

                {/* Sort By */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Sort By
                  </label>
                  <select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500 dark:bg-gray-700 dark:text-white"
                  >
                    <option value="popular">Most Popular</option>
                    <option value="newest">Newest First</option>
                    <option value="price_low">Lowest Price</option>
                    <option value="price_high">Highest Price</option>
                    <option value="rating">Highest Rated</option>
                    <option value="orders">Most Orders</option>
                  </select>
                </div>

                <Button onClick={clearFilters} variant="outline" className="w-full">
                  Clear Filters
                </Button>
              </CardContent>
            </Card>

            {/* Quick Stats */}
            <Card>
              <CardHeader>
                <CardTitle>Marketplace Stats</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Total Gigs</span>
                  <span className="font-semibold">{gigs.length}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Avg Price</span>
                  <span className="font-semibold">
                    ${gigs.length > 0 ? (gigs.reduce((sum, gig) => sum + getStartingPrice(gig.packages), 0) / gigs.length).toFixed(0) : '0'}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Top Rated</span>
                  <span className="font-semibold text-yellow-600">
                    {gigs.filter(gig => gig.rating >= 4.5).length}
                  </span>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Gigs Grid */}
          <div className="flex-1">
            {loading ? (
              <div className="flex justify-center py-12">
                <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-purple-600"></div>
              </div>
            ) : gigs.length === 0 ? (
              <Card>
                <CardContent className="text-center py-12">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">No gigs found</h3>
                  <p className="text-gray-600 dark:text-gray-400 mb-4">
                    Try adjusting your filters or check back later for new services.
                  </p>
                  <Button onClick={clearFilters}>Clear Filters</Button>
                </CardContent>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {gigs.map((gig) => (
                  <Card key={gig.id} className="hover:shadow-xl transition-all duration-300 cursor-pointer group">
                    <div 
                      className="relative overflow-hidden rounded-t-lg"
                      onClick={() => router.push(`/gigs/${gig.id}`)}
                    >
                      {gig.gallery.length > 0 ? (
                        <img
                          src={gig.gallery[0]}
                          alt={gig.title}
                          className="w-full h-48 object-cover group-hover:scale-105 transition-transform duration-300"
                        />
                      ) : (
                        <div className="w-full h-48 bg-gradient-to-br from-purple-400 to-pink-400 flex items-center justify-center">
                          <span className="text-white text-4xl">{gig.category.icon}</span>
                        </div>
                      )}
                      <div className="absolute top-4 left-4">
                        <span className="bg-black/70 text-white px-2 py-1 rounded text-xs">
                          {gig.category.name}
                        </span>
                      </div>
                      {gig.rating >= 4.5 && (
                        <div className="absolute top-4 right-4">
                          <span className="bg-yellow-500 text-white px-2 py-1 rounded-full text-xs flex items-center gap-1">
                            <Award className="h-3 w-3" />
                            Top Rated
                          </span>
                        </div>
                      )}
                    </div>

                    <CardContent className="p-6">
                      {/* Freelancer Info */}
                      <div className="flex items-center gap-3 mb-4">
                        <img
                          src={gig.freelancer.avatarUrl || '/avatars/blockchain-architect.png'}
                          alt={gig.freelancer.name}
                          className="w-10 h-10 rounded-full object-cover"
                        />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <h4 className="font-medium text-gray-900 dark:text-white text-sm">
                              {gig.freelancer.name}
                            </h4>
                            {gig.freelancer.isVerified && (
                              <span className="text-blue-500 text-xs">✓</span>
                            )}
                          </div>
                          <div className="flex items-center gap-1">
                            {renderStars(gig.freelancer.rating)}
                            <span className="text-xs text-gray-500 ml-1">
                              ({gig.freelancer.rating.toFixed(1)})
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Gig Title & Description */}
                      <h3 
                        className="font-semibold text-gray-900 dark:text-white mb-2 line-clamp-2 hover:text-purple-600 dark:hover:text-purple-400 transition-colors"
                        onClick={() => router.push(`/gigs/${gig.id}`)}
                      >
                        {gig.title}
                      </h3>
                      <p className="text-gray-600 dark:text-gray-400 text-sm mb-4 line-clamp-2">
                        {gig.description}
                      </p>

                      {/* Tags */}
                      <div className="flex flex-wrap gap-1 mb-4">
                        {gig.tags.slice(0, 3).map((tag, index) => (
                          <span
                            key={index}
                            className="bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 px-2 py-1 rounded text-xs"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>

                      {/* Stats */}
                      <div className="flex items-center gap-4 text-xs text-gray-500 dark:text-gray-400 mb-4">
                        <div className="flex items-center gap-1">
                          <Eye className="h-3 w-3" />
                          {gig.viewCount}
                        </div>
                        <div className="flex items-center gap-1">
                          <ShoppingCart className="h-3 w-3" />
                          {gig.orderCount} orders
                        </div>
                        <div className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {getFastestDelivery(gig.packages)}d delivery
                        </div>
                      </div>

                      {/* Pricing & CTA */}
                      <div className="flex justify-between items-center pt-4 border-t border-gray-200 dark:border-gray-700">
                        <div>
                          <span className="text-sm text-gray-500 dark:text-gray-400">Starting at</span>
                          <div className="text-xl font-bold text-green-600 dark:text-green-400">
                            ${getStartingPrice(gig.packages)}
                          </div>
                        </div>
                        <div className="flex gap-2">
                          <Button
                            onClick={() => router.push(`/gigs/${gig.id}`)}
                            variant="outline"
                            size="sm"
                          >
                            View Details
                          </Button>
                          {session?.user?.role === 'HIRER' && (
                            <Button
                              onClick={() => handlePurchaseGig(gig.id)}
                              size="sm"
                            >
                              Order Now
                            </Button>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}