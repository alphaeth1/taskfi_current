import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/admin-middleware';
import { prisma } from '@/lib/prisma';

// GET /api/admin/dashboard - Get comprehensive platform statistics
export async function GET(request: NextRequest) {
  try {
    const adminCheck = await requireAdmin();
    if (adminCheck) return adminCheck;

    // Get date ranges for analytics
    const now = new Date();
    const last30Days = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const last7Days = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const lastDay = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    // Parallel queries for performance
    const [
      userStats,
      userGrowth,
      jobStats,
      gigStats,
      paymentStats,
      recentUsers,
      recentJobs,
      recentGigs,
      disputedPayments,
      topFreelancers,
      topHirers,
      categoryStats,
      roleBreakdown
    ] = await Promise.all([
      // User statistics
      prisma.user.aggregate({
        _count: { id: true },
        _avg: { rating: true },
      }),

      // User growth analytics
      Promise.all([
        prisma.user.count({ where: { createdAt: { gte: last30Days } } }),
        prisma.user.count({ where: { createdAt: { gte: last7Days } } }),
        prisma.user.count({ where: { createdAt: { gte: lastDay } } }),
      ]),

      // Job statistics
      prisma.job.groupBy({
        by: ['status'],
        _count: { id: true },
        _sum: { budget: true },
      }),

      // Gig statistics
      prisma.gig.groupBy({
        by: ['status'],
        _count: { id: true },
        _sum: { orderCount: true },
      }),

      // Payment statistics
      prisma.payment.groupBy({
        by: ['status'],
        _count: { id: true },
        _sum: { amount: true },
      }),

      // Recent users (last 10)
      prisma.user.findMany({
        take: 10,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          createdAt: true,
          isVerified: true,
        },
      }),

      // Recent jobs (last 10)
      prisma.job.findMany({
        take: 10,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          title: true,
          budget: true,
          status: true,
          createdAt: true,
          user: {
            select: { name: true, email: true },
          },
        },
      }),

      // Recent gigs (last 10)
      prisma.gig.findMany({
        take: 10,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          title: true,
          price: true,
          status: true,
          createdAt: true,
          user: {
            select: { name: true, email: true },
          },
        },
      }),

      // Disputed payments
      prisma.payment.findMany({
        where: { status: 'DISPUTED' },
        include: {
          fromUser: {
            select: { name: true, email: true },
          },
          toUser: {
            select: { name: true, email: true },
          },
        },
      }),

      // Top freelancers by earnings
      prisma.payment.groupBy({
        by: ['toUserId'],
        where: { status: 'RELEASED' },
        _sum: { amount: true },
        orderBy: { _sum: { amount: 'desc' } },
        take: 10,
      }),

      // Top hirers by spending
      prisma.payment.groupBy({
        by: ['fromUserId'],
        where: { status: 'RELEASED' },
        _sum: { amount: true },
        orderBy: { _sum: { amount: 'desc' } },
        take: 10,
      }),

      // Category statistics
      prisma.category.findMany({
        include: {
          _count: {
            select: { jobs: true, gigs: true },
          },
        },
      }),

      // Role breakdown
      prisma.user.groupBy({
        by: ['role'],
        _count: { id: true },
      }),
    ]);

    // Calculate revenue and transaction volume
    const revenueStats = {
      totalVolume: paymentStats.reduce((sum, p) => sum + (p._sum.amount || 0), 0),
      totalTransactions: paymentStats.reduce((sum, p) => sum + p._count.id, 0),
      byStatus: paymentStats.reduce((acc, p) => {
        acc[p.status] = {
          count: p._count.id,
          volume: p._sum.amount || 0,
        };
        return acc;
      }, {} as Record<string, { count: number; volume: number }>),
    };

    // Calculate job success rate
    const totalJobs = jobStats.reduce((sum, j) => sum + j._count.id, 0);
    const completedJobs = jobStats.find(j => j.status === 'COMPLETED')?._count.id || 0;
    const jobSuccessRate = totalJobs > 0 ? (completedJobs / totalJobs) * 100 : 0;

    // Platform health score calculation (0-100)
    const activeUsers = await prisma.user.count({ where: { isActive: true } });
    const inactiveUsers = await prisma.user.count({ where: { isActive: false } });
    const verifiedUsers = await prisma.user.count({ where: { isVerified: true } });
    const openJobs = await prisma.job.count({ where: { status: 'OPEN' } });
    const inProgressJobs = await prisma.job.count({ where: { status: 'IN_PROGRESS' } });
    const activeGigs = await prisma.gig.count({ where: { status: 'ACTIVE' } });
    const escrowPayments = await prisma.payment.count({ where: { status: 'ESCROW' } });
    const disputedPaymentsCount = disputedPayments.length;

    // Health score factors
    const healthScore = Math.min(100, Math.max(0, 
      (activeUsers / Math.max(1, activeUsers + inactiveUsers)) * 30 +
      (verifiedUsers / Math.max(1, userStats._count.id)) * 25 +
      (inProgressJobs / Math.max(1, totalJobs)) * 20 +
      (activeGigs / Math.max(1, gigStats.reduce((sum, g) => sum + g._count.id, 0))) * 15 +
      Math.max(0, 10 - disputedPaymentsCount) // Penalty for disputes
    ));

    // Prepare dashboard data
    const dashboardData = {
      overview: {
        totalUsers: userStats._count.id,
        totalJobs: totalJobs,
        totalGigs: gigStats.reduce((sum, g) => sum + g._count.id, 0),
        totalRevenue: revenueStats.totalVolume,
        averageRating: userStats._avg.rating || 0,
      },
      users: {
        total: userStats._count.id,
        growth: {
          last30Days: userGrowth[0],
          last7Days: userGrowth[1],
          lastDay: userGrowth[2],
        },
        roleBreakdown: roleBreakdown.reduce((acc, r) => {
          acc[r.role] = r._count.id;
          return acc;
        }, {} as Record<string, number>),
        healthScore,
      },
      jobs: {
        total: totalJobs,
        successRate: jobSuccessRate,
        byStatus: jobStats.reduce((acc, j) => {
          acc[j.status] = {
            count: j._count.id,
            budget: j._sum.budget || 0,
          };
          return acc;
        }, {} as Record<string, { count: number; budget: number }>),
      },
      gigs: {
        total: gigStats.reduce((sum, g) => sum + g._count.id, 0),
        totalOrders: gigStats.reduce((sum, g) => sum + (g._sum.orderCount || 0), 0),
        byStatus: gigStats.reduce((acc, g) => {
          acc[g.status] = {
            count: g._count.id,
            orders: g._sum.orderCount || 0,
          };
          return acc;
        }, {} as Record<string, { count: number; orders: number }>),
      },
      revenue: revenueStats,
      recent: {
        users: recentUsers,
        jobs: recentJobs,
        gigs: recentGigs,
      },
      disputes: disputedPayments,
      topPerformers: {
        freelancers: topFreelancers,
        hirers: topHirers,
      },
      categories: categoryStats.map(cat => ({
        id: cat.id,
        name: cat.name,
        jobCount: cat._count.jobs,
        gigCount: cat._count.gigs,
        totalActivity: cat._count.jobs + cat._count.gigs,
      })),
      platformHealth: {
        score: Math.round(healthScore),
        factors: {
          activeUsers,
          inactiveUsers,
          verifiedUsers,
          openJobs,
          inProgressJobs,
          activeGigs,
          escrowPayments,
          disputedPayments: disputedPaymentsCount,
        },
      },
    };

    return NextResponse.json(dashboardData);
  } catch (error) {
    console.error('Admin dashboard error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}