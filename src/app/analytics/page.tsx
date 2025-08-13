'use client';

import { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';
import { useRouter } from 'next/navigation';
import {
  TrendingUp,
  TrendingDown,
  DollarSign,
  Users,
  Briefcase,
  Package,
  Calendar,
  BarChart3,
  PieChart,
  Activity,
  Star,
  Target,
} from 'lucide-react';

interface AnalyticsData {
  overview: {
    totalEarnings?: number;
    totalSpent?: number;
    totalUsers?: number;
    newUsers?: number;
    totalJobs: number;
    newJobs?: number;
    totalGigs?: number;
    newGigs?: number;
    totalRevenue?: number;
    totalTransactions?: number;
    totalApplications?: number;
    successRate?: number;
    totalOrders?: number;
    completedJobs?: number;
    activeJobs?: number;
    averageJobBudget?: number;
  };
  trends: {
    dailyEarnings?: any[];
    dailyRevenue?: any[];
    dailySpending?: any[];
    userGrowth?: any[];
    categoryAnalytics?: any[];
    categoryPerformance?: any[];
    categorySpending?: any[];
  };
  gigs?: any[];
  recentJobs?: any[];
  leaderboards?: {
    topFreelancers: any[];
    topHirers: any[];
  };
}

export default function AnalyticsPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedPeriod, setSelectedPeriod] = useState('30');
  const [userType, setUserType] = useState('all');

  useEffect(() => {
    if (status === 'loading') return;
    if (!session) {
      router.push('/auth/signin');
      return;
    }
    loadAnalytics();
  }, [session, status, selectedPeriod, userType]);

  const loadAnalytics = async () => {
    try {
      const params = new URLSearchParams({
        period: selectedPeriod,
        userType,
      });

      const response = await fetch(`/api/analytics?${params}`);
      if (response.ok) {
        const data = await response.json();
        setAnalytics(data);
      }
    } catch (error) {
      console.error('Error loading analytics:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0,
    }).format(amount);
  };

  const StatCard = ({ 
    title, 
    value, 
    change, 
    icon: Icon, 
    color = 'blue',
    format = 'number' 
  }: {
    title: string;
    value: number | undefined;
    change?: number;
    icon: any;
    color?: string;
    format?: 'number' | 'currency' | 'percentage';
  }) => {
    const formatValue = (val: number | undefined) => {
      if (val === undefined) return 'N/A';
      switch (format) {
        case 'currency':
          return formatCurrency(val);
        case 'percentage':
          return `${val}%`;
        default:
          return val.toLocaleString();
      }
    };

    const colorClasses = {
      blue: 'bg-blue-100 text-blue-600',
      green: 'bg-green-100 text-green-600',
      purple: 'bg-purple-100 text-purple-600',
      orange: 'bg-orange-100 text-orange-600',
      red: 'bg-red-100 text-red-600',
    };

    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-gray-600">{title}</p>
            <p className="text-2xl font-bold text-gray-900 mt-1">
              {formatValue(value)}
            </p>
            {change !== undefined && (
              <div className={`flex items-center mt-2 text-sm ${
                change >= 0 ? 'text-green-600' : 'text-red-600'
              }`}>
                {change >= 0 ? (
                  <TrendingUp className="w-4 h-4 mr-1" />
                ) : (
                  <TrendingDown className="w-4 h-4 mr-1" />
                )}
                <span>{Math.abs(change)}% from last period</span>
              </div>
            )}
          </div>
          <div className={`p-3 rounded-lg ${colorClasses[color as keyof typeof colorClasses]}`}>
            <Icon className="w-6 h-6" />
          </div>
        </div>
      </div>
    );
  };

  if (status === 'loading' || isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!analytics) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-xl font-semibold text-gray-900 mb-2">No analytics data available</h2>
          <button
            onClick={loadAnalytics}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const isAdmin = session?.user?.role === 'ADMIN';
  const isFreelancer = session?.user?.role === 'FREELANCER';
  const isHirer = session?.user?.role === 'HIRER';

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-6">
        {/* Header */}
        <div className="mb-8">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center space-x-3 mb-4 sm:mb-0">
              <div className="p-2 bg-blue-100 rounded-lg">
                <BarChart3 className="w-8 h-8 text-blue-600" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Analytics Dashboard</h1>
                <p className="text-gray-600">
                  {isAdmin ? 'Platform insights and performance metrics' : 
                   isFreelancer ? 'Your earnings and performance analytics' :
                   'Your spending and project analytics'}
                </p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <select
                value={selectedPeriod}
                onChange={(e) => setSelectedPeriod(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="7">Last 7 days</option>
                <option value="30">Last 30 days</option>
                <option value="90">Last 90 days</option>
                <option value="365">Last year</option>
              </select>
              
              {isAdmin && (
                <select
                  value={userType}
                  onChange={(e) => setUserType(e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="all">Platform Overview</option>
                  <option value="freelancer">Freelancer View</option>
                  <option value="hirer">Hirer View</option>
                </select>
              )}
            </div>
          </div>
        </div>

        {/* Overview Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {isAdmin && analytics.overview.totalUsers !== undefined && (
            <>
              <StatCard
                title="Total Users"
                value={analytics.overview.totalUsers}
                icon={Users}
                color="blue"
              />
              <StatCard
                title="Platform Revenue"
                value={analytics.overview.totalRevenue}
                icon={DollarSign}
                color="green"
                format="currency"
              />
              <StatCard
                title="Total Jobs"
                value={analytics.overview.totalJobs}
                icon={Briefcase}
                color="purple"
              />
              <StatCard
                title="Total Gigs"
                value={analytics.overview.totalGigs}
                icon={Package}
                color="orange"
              />
            </>
          )}
          
          {isFreelancer && (
            <>
              <StatCard
                title="Total Earnings"
                value={analytics.overview.totalEarnings}
                icon={DollarSign}
                color="green"
                format="currency"
              />
              <StatCard
                title="Completed Jobs"
                value={analytics.overview.totalJobs}
                icon={Briefcase}
                color="blue"
              />
              <StatCard
                title="Success Rate"
                value={analytics.overview.successRate}
                icon={Target}
                color="purple"
                format="percentage"
              />
              <StatCard
                title="Gig Orders"
                value={analytics.overview.totalOrders}
                icon={Package}
                color="orange"
              />
            </>
          )}
          
          {isHirer && (
            <>
              <StatCard
                title="Total Spent"
                value={analytics.overview.totalSpent}
                icon={DollarSign}
                color="red"
                format="currency"
              />
              <StatCard
                title="Posted Jobs"
                value={analytics.overview.totalJobs}
                icon={Briefcase}
                color="blue"
              />
              <StatCard
                title="Completed Projects"
                value={analytics.overview.completedJobs}
                icon={Target}
                color="green"
              />
              <StatCard
                title="Average Budget"
                value={analytics.overview.averageJobBudget}
                icon={Activity}
                color="purple"
                format="currency"
              />
            </>
          )}
        </div>

        {/* Charts and Detailed Analytics */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* Category Performance */}
          {(analytics.trends.categoryAnalytics || analytics.trends.categoryPerformance || analytics.trends.categorySpending) && (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <PieChart className="w-5 h-5 mr-2" />
                Category Performance
              </h3>
              <div className="space-y-4">
                {(analytics.trends.categoryAnalytics || 
                  analytics.trends.categoryPerformance || 
                  analytics.trends.categorySpending || []).slice(0, 5).map((category: any, index: number) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div>
                      <p className="font-medium text-gray-900">{category.name || category.category}</p>
                      <p className="text-sm text-gray-600">
                        {category.jobCount || category.job_count || 0} jobs
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="font-semibold text-gray-900">
                        {formatCurrency(category.totalBudget || category.total_earned || category.total_spent || 0)}
                      </p>
                      {category.totalOrders && (
                        <p className="text-sm text-gray-600">{category.totalOrders} orders</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recent Activity */}
          {(analytics.gigs || analytics.recentJobs) && (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <Activity className="w-5 h-5 mr-2" />
                {analytics.gigs ? 'Top Gigs' : 'Recent Jobs'}
              </h3>
              <div className="space-y-4">
                {(analytics.gigs || analytics.recentJobs || []).map((item: any, index: number) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex-1">
                      <p className="font-medium text-gray-900 truncate">{item.title}</p>
                      <div className="flex items-center space-x-4 text-sm text-gray-600 mt-1">
                        {item.rating && (
                          <div className="flex items-center">
                            <Star className="w-4 h-4 text-yellow-400 mr-1" />
                            <span>{item.rating.toFixed(1)}</span>
                          </div>
                        )}
                        {item.orderCount !== undefined && (
                          <span>{item.orderCount} orders</span>
                        )}
                        {item.viewCount !== undefined && (
                          <span>{item.viewCount} views</span>
                        )}
                        {item.budget && (
                          <span>{formatCurrency(item.budget)}</span>
                        )}
                      </div>
                    </div>
                    <div className="text-right ml-4">
                      {item.status && (
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                          {
                            'OPEN': 'bg-green-100 text-green-800',
                            'IN_PROGRESS': 'bg-blue-100 text-blue-800',
                            'COMPLETED': 'bg-gray-100 text-gray-800',
                            'ACTIVE': 'bg-green-100 text-green-800',
                          }[item.status] || 'bg-gray-100 text-gray-800'
                        }`}>
                          {item.status.replace('_', ' ')}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Leaderboards (Admin Only) */}
        {isAdmin && analytics.leaderboards && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Freelancers</h3>
              <div className="space-y-3">
                {analytics.leaderboards.topFreelancers.map((freelancer: any, index: number) => (
                  <div key={freelancer.id} className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center text-white font-medium ${
                        index === 0 ? 'bg-yellow-500' : 
                        index === 1 ? 'bg-gray-400' : 
                        index === 2 ? 'bg-orange-500' : 'bg-blue-500'
                      }`}>
                        {index + 1}
                      </div>
                      <div>
                        <p className="font-medium text-gray-900">{freelancer.name}</p>
                        <p className="text-sm text-gray-600">@{freelancer.username}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="font-semibold text-gray-900">
                        {formatCurrency(freelancer.totalEarned)}
                      </p>
                      <div className="flex items-center text-sm text-gray-600">
                        <Star className="w-4 h-4 text-yellow-400 mr-1" />
                        <span>{freelancer.rating.toFixed(1)}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Hirers</h3>
              <div className="space-y-3">
                {analytics.leaderboards.topHirers.map((hirer: any, index: number) => (
                  <div key={hirer.id} className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center text-white font-medium ${
                        index === 0 ? 'bg-yellow-500' : 
                        index === 1 ? 'bg-gray-400' : 
                        index === 2 ? 'bg-orange-500' : 'bg-blue-500'
                      }`}>
                        {index + 1}
                      </div>
                      <div>
                        <p className="font-medium text-gray-900">{hirer.name}</p>
                        <p className="text-sm text-gray-600">@{hirer.username}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="font-semibold text-gray-900">
                        {formatCurrency(hirer.totalSpent)}
                      </p>
                      <div className="flex items-center text-sm text-gray-600">
                        <Star className="w-4 h-4 text-yellow-400 mr-1" />
                        <span>{hirer.rating.toFixed(1)}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}