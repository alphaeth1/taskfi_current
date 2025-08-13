import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/admin-middleware';
import { prisma } from '@/lib/prisma';
import { z } from 'zod';

const updateUserSchema = z.object({
  name: z.string().optional(),
  email: z.string().email().optional(),
  role: z.enum(['ADMIN', 'FREELANCER', 'HIRER']).optional(),
  isActive: z.boolean().optional(),
  isVerified: z.boolean().optional(),
});

// GET /api/admin/users/[id] - Get detailed user information
export async function GET(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  
  try {
    const adminCheck = await requireAdmin();
    if (adminCheck) return adminCheck;

    const user = await prisma.user.findUnique({
      where: { id: params.id },
      include: {
        jobsPosted: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            title: true,
            budget: true,
            status: true,
            createdAt: true,
          },
        },
        jobApplications: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            status: true,
            createdAt: true,
            job: {
              select: {
                id: true,
                title: true,
                budget: true,
              },
            },
          },
        },
        gigs: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            title: true,
            price: true,
            status: true,
            createdAt: true,
          },
        },
        sentPayments: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            amount: true,
            status: true,
            createdAt: true,
            toUser: {
              select: { name: true, email: true },
            },
          },
        },
        receivedPayments: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            amount: true,
            status: true,
            createdAt: true,
            fromUser: {
              select: { name: true, email: true },
            },
          },
        },
        reviews: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            rating: true,
            comment: true,
            createdAt: true,
            reviewee: {
              select: { name: true, email: true },
            },
          },
        },
        reviewsReceived: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            rating: true,
            comment: true,
            createdAt: true,
            reviewer: {
              select: { name: true, email: true },
            },
          },
        },
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
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // Calculate additional statistics
    const paymentStats = {
      totalSent: await prisma.payment.aggregate({
        where: { fromUserId: params.id, status: 'RELEASED' },
        _sum: { amount: true },
      }),
      totalReceived: await prisma.payment.aggregate({
        where: { toUserId: params.id, status: 'RELEASED' },
        _sum: { amount: true },
      }),
      averageRating: await prisma.review.aggregate({
        where: { revieweeId: params.id },
        _avg: { rating: true },
      }),
    };

    return NextResponse.json({
      user,
      stats: {
        payments: {
          totalSent: paymentStats.totalSent._sum.amount || 0,
          totalReceived: paymentStats.totalReceived._sum.amount || 0,
        },
        averageRating: paymentStats.averageRating._avg.rating || 0,
        counts: user._count,
      },
    });
  } catch (error) {
    console.error('Admin get user error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

// PUT /api/admin/users/[id] - Update user details
export async function PUT(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  
  try {
    const adminCheck = await requireAdmin();
    if (adminCheck) return adminCheck;

    const body = await request.json();
    const updateData = updateUserSchema.parse(body);

    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id: params.id },
    });

    if (!existingUser) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // Check email uniqueness if updating email
    if (updateData.email && updateData.email !== existingUser.email) {
      const emailExists = await prisma.user.findFirst({
        where: { email: updateData.email },
      });

      if (emailExists) {
        return NextResponse.json({ error: 'Email already in use' }, { status: 409 });
      }
    }

    const updatedUser = await prisma.user.update({
      where: { id: params.id },
      data: updateData,
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

    return NextResponse.json({ user: updatedUser });
  } catch (error) {
    console.error('Admin update user error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

// DELETE /api/admin/users/[id] - Delete user (admin only)
export async function DELETE(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  
  try {
    const adminCheck = await requireAdmin();
    if (adminCheck) return adminCheck;

    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id: params.id },
    });

    if (!existingUser) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // Check if user has active transactions or jobs
    const hasActiveTransactions = await prisma.payment.findFirst({
      where: {
        OR: [
          { fromUserId: params.id },
          { toUserId: params.id },
        ],
        status: { in: ['PENDING', 'ESCROW'] },
      },
    });

    if (hasActiveTransactions) {
      return NextResponse.json(
        { error: 'Cannot delete user with active transactions' },
        { status: 409 }
      );
    }

    // Soft delete by deactivating instead of hard delete
    await prisma.user.update({
      where: { id: params.id },
      data: {
        isActive: false,
        email: `deleted_${Date.now()}_${existingUser.email}`,
        name: `[DELETED] ${existingUser.name}`,
      },
    });

    return NextResponse.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Admin delete user error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}