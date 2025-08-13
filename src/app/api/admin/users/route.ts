import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/admin-middleware';
import { prisma } from '@/lib/prisma';
import { z } from 'zod';

// Validation schemas
const querySchema = z.object({
  page: z.string().optional().default('1'),
  limit: z.string().optional().default('20'),
  search: z.string().optional(),
  role: z.enum(['ADMIN', 'FREELANCER', 'HIRER']).optional(),
  status: z.enum(['active', 'inactive', 'verified', 'unverified']).optional(),
  sortBy: z.enum(['createdAt', 'name', 'email', 'rating']).optional().default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
});

const updateUserSchema = z.object({
  name: z.string().optional(),
  email: z.string().email().optional(),
  role: z.enum(['ADMIN', 'FREELANCER', 'HIRER']).optional(),
  isActive: z.boolean().optional(),
  isVerified: z.boolean().optional(),
});

// GET /api/admin/users - Get paginated user list with filters
export async function GET(request: NextRequest) {
  try {
    const adminCheck = await requireAdmin();
    if (adminCheck) return adminCheck;

    const { searchParams } = new URL(request.url);
    const query = querySchema.parse({
      page: searchParams.get('page') || '1',
      limit: searchParams.get('limit') || '20',
      search: searchParams.get('search') || undefined,
      role: searchParams.get('role') || undefined,
      status: searchParams.get('status') || undefined,
      sortBy: searchParams.get('sortBy') || 'createdAt',
      sortOrder: searchParams.get('sortOrder') || 'desc',
    });

    const page = parseInt(query.page);
    const limit = Math.min(parseInt(query.limit), 100);
    const skip = (page - 1) * limit;

    // Build where clause
    const where: any = {};

    if (query.role) {
      where.role = query.role;
    }

    if (query.status === 'active') {
      where.isActive = true;
    } else if (query.status === 'inactive') {
      where.isActive = false;
    } else if (query.status === 'verified') {
      where.isVerified = true;
    } else if (query.status === 'unverified') {
      where.isVerified = false;
    }

    if (query.search) {
      where.OR = [
        { name: { contains: query.search, mode: 'insensitive' } },
        { email: { contains: query.search, mode: 'insensitive' } },
        { walletAddress: { contains: query.search, mode: 'insensitive' } },
      ];
    }

    // Build orderBy
    const orderBy: any = {};
    orderBy[query.sortBy] = query.sortOrder;

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        skip,
        take: limit,
        orderBy,
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
      }),
      prisma.user.count({ where }),
    ]);

    // Get status counts for filters
    const statusCounts = {
      total: await prisma.user.count({ where: { ...where, OR: undefined } }),
      active: await prisma.user.count({ where: { ...where, isActive: true, OR: undefined } }),
      inactive: await prisma.user.count({ where: { ...where, isActive: false, OR: undefined } }),
      verified: await prisma.user.count({ where: { ...where, isVerified: true, OR: undefined } }),
      unverified: await prisma.user.count({ where: { ...where, isVerified: false, OR: undefined } }),
    };

    return NextResponse.json({
      users,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasNext: page * limit < total,
        hasPrev: page > 1,
      },
      filters: {
        statusCounts,
      },
    });
  } catch (error) {
    console.error('Admin get users error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

// POST /api/admin/users - Create new user (admin only)
export async function POST(request: NextRequest) {
  try {
    const adminCheck = await requireAdmin();
    if (adminCheck) return adminCheck;

    const body = await request.json();
    const { name, email, role, walletAddress } = z.object({
      name: z.string().min(1),
      email: z.string().email(),
      role: z.enum(['ADMIN', 'FREELANCER', 'HIRER']),
      walletAddress: z.string().optional(),
    }).parse(body);

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { email },
          ...(walletAddress ? [{ walletAddress }] : []),
        ],
      },
    });

    if (existingUser) {
      return NextResponse.json({ error: 'User already exists' }, { status: 409 });
    }

    const user = await prisma.user.create({
      data: {
        name,
        email,
        role,
        walletAddress,
        isVerified: true, // Admin-created users are auto-verified
      },
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

    return NextResponse.json({ user }, { status: 201 });
  } catch (error) {
    console.error('Admin create user error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}