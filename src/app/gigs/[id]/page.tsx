'use client';

import { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';
import { useRouter } from 'next/navigation';
import { 
  ArrowLeft, 
  Star, 
  Clock, 
  Package, 
  Shield, 
  CheckCircle,
  MessageSquare,
  Heart,
  Share2,
  Flag,
  User,
  Calendar,
  TrendingUp
} from 'lucide-react';

interface GigPackage {
  name: string;
  description: string;
  price: number;
  deliveryDays: number;
  revisions: number;
  features: string[];
}

interface Gig {
  id: string;
  title: string;
  description: string;
  packages: GigPackage[];
  gallery: string[];
  tags: string[];
  rating: number;
  orderCount: number;
  viewCount: number;
  createdAt: string;
  freelancer: {
    id: string;
    name: string;
    username: string;
    avatarUrl?: string;
    rating: number;
    totalEarned: number;
    isVerified: boolean;
    categories: string[];
  };
  category: {
    id: string;
    name: string;
  };
}

export default function GigDetailPage({ params }: { params: { id: string } }) {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [gig, setGig] = useState<Gig | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedPackage, setSelectedPackage] = useState(0);
  const [isOrdering, setIsOrdering] = useState(false);

  useEffect(() => {
    loadGigDetails();
  }, [params.id]);

  const loadGigDetails = async () => {
    try {
      const response = await fetch(`/api/gigs/${params.id}`);
      if (response.ok) {
        const data = await response.json();
        setGig(data);
      } else {
        console.error('Failed to load gig details');
      }
    } catch (error) {
      console.error('Error loading gig details:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleOrder = async () => {
    if (!session) {
      router.push('/auth/signin');
      return;
    }

    if (!gig) return;

    setIsOrdering(true);
    try {
      const response = await fetch(`/api/gigs/${gig.id}/order`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          packageIndex: selectedPackage,
          packageData: gig.packages[selectedPackage],
        }),
      });

      if (response.ok) {
        const data = await response.json();
        router.push(`/orders/${data.orderId}`);
      } else {
        console.error('Failed to create order');
      }
    } catch (error) {
      console.error('Error creating order:', error);
    } finally {
      setIsOrdering(false);
    }
  };

  const handleContactFreelancer = () => {
    if (!session) {
      router.push('/auth/signin');
      return;
    }
    // In a real app, this would open a direct message interface
    console.log('Contact freelancer:', gig?.freelancer.id);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!gig) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Gig not found</h2>
          <button
            onClick={() => router.back()}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Go Back
          </button>
        </div>
      </div>
    );
  }

  const currentPackage = gig.packages[selectedPackage];

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-6">
        {/* Header */}
        <button
          onClick={() => router.back()}
          className="flex items-center text-gray-600 hover:text-gray-900 mb-6 transition-colors"
        >
          <ArrowLeft className="w-5 h-5 mr-2" />
          Back to Browse
        </button>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2">
            {/* Gig Info */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
              <div className="flex items-center justify-between mb-4">
                <span className="px-3 py-1 bg-purple-100 text-purple-800 text-sm font-medium rounded-full">
                  {gig.category.name}
                </span>
                <div className="flex items-center space-x-2">
                  <button className="p-2 text-gray-400 hover:text-red-500 transition-colors">
                    <Heart className="w-5 h-5" />
                  </button>
                  <button className="p-2 text-gray-400 hover:text-blue-500 transition-colors">
                    <Share2 className="w-5 h-5" />
                  </button>
                  <button className="p-2 text-gray-400 hover:text-red-500 transition-colors">
                    <Flag className="w-5 h-5" />
                  </button>
                </div>
              </div>

              <h1 className="text-2xl font-bold text-gray-900 mb-4">{gig.title}</h1>

              {/* Freelancer Info */}
              <div className="flex items-center space-x-4 mb-6 p-4 bg-gray-50 rounded-lg">
                {gig.freelancer.avatarUrl ? (
                  <img
                    src={gig.freelancer.avatarUrl}
                    alt={gig.freelancer.name}
                    className="w-12 h-12 rounded-full object-cover"
                  />
                ) : (
                  <div className="w-12 h-12 rounded-full bg-gradient-to-r from-purple-500 to-blue-500 flex items-center justify-center text-white font-medium text-lg">
                    {gig.freelancer.name.charAt(0).toUpperCase()}
                  </div>
                )}
                <div className="flex-1">
                  <div className="flex items-center space-x-2">
                    <h3 className="font-semibold text-gray-900">{gig.freelancer.name}</h3>
                    {gig.freelancer.isVerified && (
                      <CheckCircle className="w-5 h-5 text-blue-500" />
                    )}
                  </div>
                  <div className="flex items-center space-x-4 text-sm text-gray-600">
                    <div className="flex items-center">
                      <Star className="w-4 h-4 text-yellow-400 mr-1" />
                      <span>{gig.freelancer.rating.toFixed(1)}</span>
                    </div>
                    <span>${gig.freelancer.totalEarned.toLocaleString()} earned</span>
                    <span>@{gig.freelancer.username}</span>
                  </div>
                </div>
                <button
                  onClick={handleContactFreelancer}
                  className="flex items-center space-x-2 bg-gray-200 text-gray-700 px-4 py-2 rounded-lg hover:bg-gray-300 transition-colors"
                >
                  <MessageSquare className="w-4 h-4" />
                  <span>Contact</span>
                </button>
              </div>

              {/* Gallery */}
              {gig.gallery.length > 0 && (
                <div className="mb-6">
                  <h3 className="text-lg font-semibold text-gray-900 mb-3">Gallery</h3>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    {gig.gallery.map((image, index) => (
                      <div key={index} className="aspect-video bg-gray-200 rounded-lg overflow-hidden">
                        <img
                          src={image}
                          alt={`Gallery ${index + 1}`}
                          className="w-full h-full object-cover"
                        />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Description */}
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-3">About This Gig</h3>
                <div className="prose prose-gray max-w-none">
                  <p className="text-gray-700 whitespace-pre-wrap">{gig.description}</p>
                </div>
              </div>

              {/* Tags */}
              {gig.tags.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-3">Skills & Expertise</h3>
                  <div className="flex flex-wrap gap-2">
                    {gig.tags.map((tag, index) => (
                      <span
                        key={index}
                        className="px-3 py-1 bg-blue-100 text-blue-800 text-sm rounded-full"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Stats */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Gig Statistics</h3>
              <div className="grid grid-cols-3 gap-6">
                <div className="text-center">
                  <div className="flex items-center justify-center w-12 h-12 bg-blue-100 rounded-lg mx-auto mb-2">
                    <TrendingUp className="w-6 h-6 text-blue-600" />
                  </div>
                  <p className="text-2xl font-bold text-gray-900">{gig.orderCount}</p>
                  <p className="text-sm text-gray-600">Orders Completed</p>
                </div>
                <div className="text-center">
                  <div className="flex items-center justify-center w-12 h-12 bg-yellow-100 rounded-lg mx-auto mb-2">
                    <Star className="w-6 h-6 text-yellow-600" />
                  </div>
                  <p className="text-2xl font-bold text-gray-900">{gig.rating.toFixed(1)}</p>
                  <p className="text-sm text-gray-600">Average Rating</p>
                </div>
                <div className="text-center">
                  <div className="flex items-center justify-center w-12 h-12 bg-green-100 rounded-lg mx-auto mb-2">
                    <User className="w-6 h-6 text-green-600" />
                  </div>
                  <p className="text-2xl font-bold text-gray-900">{gig.viewCount}</p>
                  <p className="text-sm text-gray-600">Total Views</p>
                </div>
              </div>
            </div>
          </div>

          {/* Sidebar - Packages */}
          <div className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 sticky top-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Choose a Package</h3>
              
              {/* Package Tabs */}
              <div className="flex space-x-1 mb-6 bg-gray-100 rounded-lg p-1">
                {gig.packages.map((pkg, index) => (
                  <button
                    key={index}
                    onClick={() => setSelectedPackage(index)}
                    className={`flex-1 py-2 px-3 text-sm font-medium rounded-md transition-colors ${
                      selectedPackage === index
                        ? 'bg-white text-blue-600 shadow-sm'
                        : 'text-gray-600 hover:text-gray-900'
                    }`}
                  >
                    {pkg.name}
                  </button>
                ))}
              </div>

              {/* Selected Package Details */}
              <div className="mb-6">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-semibold text-gray-900">{currentPackage.name}</h4>
                  <div className="text-right">
                    <p className="text-2xl font-bold text-gray-900">${currentPackage.price}</p>
                  </div>
                </div>
                
                <p className="text-gray-600 text-sm mb-4">{currentPackage.description}</p>
                
                <div className="flex items-center justify-between mb-4 text-sm text-gray-600">
                  <div className="flex items-center">
                    <Clock className="w-4 h-4 mr-1" />
                    <span>{currentPackage.deliveryDays} day delivery</span>
                  </div>
                  <div className="flex items-center">
                    <Package className="w-4 h-4 mr-1" />
                    <span>{currentPackage.revisions} revisions</span>
                  </div>
                </div>

                {/* Features */}
                <div className="space-y-2 mb-6">
                  {currentPackage.features.map((feature, index) => (
                    <div key={index} className="flex items-center space-x-2 text-sm">
                      <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
                      <span className="text-gray-700">{feature}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Order Button */}
              <button
                onClick={handleOrder}
                disabled={isOrdering || session?.user?.id === gig.freelancer.id}
                className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center space-x-2"
              >
                {isOrdering ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                    <span>Processing...</span>
                  </>
                ) : session?.user?.id === gig.freelancer.id ? (
                  <span>Your Own Gig</span>
                ) : (
                  <>
                    <span>Order Now</span>
                    <span>(${currentPackage.price})</span>
                  </>
                )}
              </button>

              {/* Security Note */}
              <div className="mt-4 p-3 bg-gray-50 rounded-lg">
                <div className="flex items-start space-x-2">
                  <Shield className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <div className="text-sm text-gray-600">
                    <p className="font-medium text-gray-900">Secure Payment</p>
                    <p>Your payment is protected by TaskFi's escrow system until work is completed.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}