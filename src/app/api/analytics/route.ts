import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

// GET /api/analytics - Get analytics data for user or platform
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const period = searchParams.get('period') || '30'; // days
    const userId = searchParams.get('userId');
    const isAdmin = session.user.role === 'ADMIN';

    // Calculate date range
    const days = parseInt(period);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    let analytics;

    if (userId && isAdmin) {
      // Admin requesting specific user analytics
      analytics = await getUserAnalytics(userId, startDate, session.user.role);
    } else if (isAdmin && !userId) {
      // Admin requesting platform analytics
      analytics = await getPlatformAnalytics(startDate);
    } else {
      // Regular user requesting their own analytics
      const currentUser = await prisma.user.findUnique({
        where: { email: session.user.email },
      });
      
      if (!currentUser) {
        return NextResponse.json({ error: 'User not found' }, { status: 404 });
      }

      // User-specific analytics
      analytics = await getUserAnalytics(currentUser.id, startDate, currentUser.role);
    }

    return NextResponse.json(analytics);
  } catch (error) {
    console.error('Error fetching analytics:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

async function getPlatformAnalytics(startDate: Date) {
  // Platform overview stats
  const totalUsers = await prisma.user.count();
  const totalJobs = await prisma.job.count();
  const totalGigs = await prisma.gig.count();
  const totalRevenue = await prisma.payment.aggregate({
    where: { status: 'RELEASED' },
    _sum: { amount: true },
  });

  // Growth metrics
  const newUsers = await prisma.user.count({
    where: { createdAt: { gte: startDate } },
  });
  
  const newJobs = await prisma.job.count({
    where: { createdAt: { gte: startDate } },
  });

  const newGigs = await prisma.gig.count({
    where: { createdAt: { gte: startDate } },
  });

  // Revenue in period
  const revenueInPeriod = await prisma.payment.aggregate({
    where: {
      status: 'RELEASED',
      createdAt: { gte: startDate },
    },
    _sum: { amount: true },
  });

  // Daily revenue trend
  const dailyRevenue = await prisma.$queryRaw`
    SELECT 
      DATE(created_at) as date,
      COUNT(*) as transactions,
      SUM(amount) as revenue
    FROM payments 
    WHERE status = 'RELEASED' 
      AND created_at >= ${startDate.toISOString()}
    GROUP BY DATE(created_at)
    ORDER BY date ASC
  `;

  // User activity breakdown
  const usersByRole = await prisma.user.groupBy({
    by: ['role'],
    _count: { id: true },
  });

  const jobsByStatus = await prisma.job.groupBy({
    by: ['status'],
    _count: { id: true },
  });

  return {
    overview: {
      totalUsers,
      totalJobs,
      totalGigs,
      totalRevenue: totalRevenue._sum.amount || 0,
    },
    growth: {
      newUsers,
      newJobs,
      newGigs,
      revenueInPeriod: revenueInPeriod._sum.amount || 0,
    },
    trends: {
      dailyRevenue,
    },
    breakdown: {
      usersByRole: usersByRole.reduce((acc, item) => {
        acc[item.role] = item._count.id;
        return acc;
      }, {} as Record<string, number>),
      jobsByStatus: jobsByStatus.reduce((acc, item) => {
        acc[item.status] = item._count.id;
        return acc;
      }, {} as Record<string, number>),
    },
  };
}

async function getUserAnalytics(userId: string, startDate: Date, userRole: string) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: {
      _count: {
        select: {
          jobsPosted: true,
          jobApplications: true,
          gigs: true,
          sentPayments: true,
          receivedPayments: true,
          reviews: true,
          reviewsReceived: true,
        },
      },
    },
  });

  if (!user) {
    throw new Error('User not found');
  }

  // User-specific metrics based on role
  let roleSpecificData = {};

  if (userRole === 'FREELANCER') {
    // Freelancer analytics
    const earnings = await prisma.payment.aggregate({
      where: {
        toUserId: userId,
        status: 'RELEASED',
        createdAt: { gte: startDate },
      },
      _sum: { amount: true },
    });

    const completedJobs = await prisma.jobApplication.count({
      where: {
        userId,
        status: 'ACCEPTED',
        job: { status: 'COMPLETED' },
      },
    });

    const dailyEarnings = await prisma.$queryRaw`
      SELECT 
        DATE(created_at) as date,
        SUM(amount) as earnings
      FROM payments 
      WHERE to_user_id = ${userId} AND status = 'RELEASED' 
        AND created_at >= ${startDate.toISOString()}
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `;

    roleSpecificData = {
      totalEarnings: earnings._sum.amount || 0,
      completedJobs,
      dailyEarnings,
      successRate: user._count.jobApplications > 0 
        ? (completedJobs / user._count.jobApplications) * 100 
        : 0,
    };
  } else if (userRole === 'HIRER') {
    // Hirer analytics
    const spending = await prisma.payment.aggregate({
      where: {
        fromUserId: userId,
        status: 'RELEASED',
        createdAt: { gte: startDate },
      },
      _sum: { amount: true },
    });

    const completedJobs = await prisma.job.count({
      where: {
        userId,
        status: 'COMPLETED',
      },
    });

    roleSpecificData = {
      totalSpending: spending._sum.amount || 0,
      jobsPosted: user._count.jobsPosted,
      completedJobs,
      completionRate: user._count.jobsPosted > 0 
        ? (completedJobs / user._count.jobsPosted) * 100 
        : 0,
    };
  }

  // Average rating
  const avgRating = await prisma.review.aggregate({
    where: { revieweeId: userId },
    _avg: { rating: true },
  });

  return {
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      counts: user._count,
    },
    period: {
      days: Math.ceil((new Date().getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24)),
      startDate: startDate.toISOString(),
      endDate: new Date().toISOString(),
    },
    metrics: {
      averageRating: avgRating._avg.rating || 0,
      ...roleSpecificData,
    },
  };
}