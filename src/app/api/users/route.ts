import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, WalletVerificationService } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'

const createUserSchema = z.object({
  walletAddress: z.string().min(32).max(44),
  name: z.string().min(1).max(100),
  username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_]+$/),
  bio: z.string().max(500).optional(),
  role: z.enum(['FREELANCER', 'HIRER']),
  categories: z.array(z.string()).max(3).optional(),
  avatarUrl: z.string().url().optional(),
})

const updateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_]+$/).optional(),
  bio: z.string().max(500).optional(),
  categories: z.array(z.string()).max(3).optional(),
  avatarUrl: z.string().url().optional(),
})

const getUsersQuerySchema = z.object({
  role: z.enum(['FREELANCER', 'HIRER', 'ADMIN']).optional(),
  search: z.string().optional(),
  page: z.string().default('1'),
  limit: z.string().default('10'),
  verified: z.string().optional(),
})

// GET /api/users - Get users with pagination and filtering
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     const { searchParams } = new URL(request.url)
    const query = getUsersQuerySchema.parse({
      role: searchParams.get('role'),
      search: searchParams.get('search'),
      page: searchParams.get('page'),
      limit: searchParams.get('limit'),
      verified: searchParams.get('verified'),
    })

    const page = parseInt(query.page)
    const limit = Math.min(parseInt(query.limit), 50) // Max 50 per page
    const skip = (page - 1) * limit

    const where: any = { if (query.role) {
      where.role = query.role
     if (query.search) {
      where.OR = [
        { name: { contains: query.search, mode: 'insensitive' } },
        { username: { contains: query.search, mode: 'insensitive' } },
        { bio: { contains: query.search, mode: 'insensitive' } },
      ]
     if (query.verified !== undefined) {
      where.isVerified = query.verified === 'true'
     where.isActive = true // Only return active users

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        select: {
          id: true,
          name: true,
          username: true,
          bio: true,
          role: true,
          avatarUrl: true,
          rating: true,
          totalEarned: true,
          totalSpent: true,
          isVerified: true,
          categories: true,
          createdAt: true,
          _count: {
            select: {
              gigsAsFreelancer: true,
              jobsAsHirer: true,
              receivedReviews: true,
            },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.user.count({ where }),
    ])

    return NextResponse.json({
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error('Get users error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/users - Create new user
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const userData = createUserSchema.parse(body)

    // Check if username is available
    const isAvailable = await WalletVerificationService.isUsernameAvailable(userData.username)
    if (!isAvailable) {
      return NextResponse.json({ error: "Internal server}
 error" }, { status: 400 });
    }

    // Check if wallet address is already registered
    const existingUser = await WalletVerificationService.getUserByWallet(userData.walletAddress)
    if (existingUser) {
      return NextResponse.json({ error: "Internal server}
 error" }, { status: 400 });
     // Create user
    const user = await WalletVerificationService.createUser(userData)

    return NextResponse.json({ user }, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: "Validation error", details: error.errors }, { status: 400 });
     console.error('Create user error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // PUT /api/users - Update current user
export async function PUT(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     const body = await request.json()
    const updateData = updateUserSchema.parse(body)

    const user = await WalletVerificationService.updateUser(session.user.id, updateData)

    return NextResponse.json({ user });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Validation error', details: error.errors },
        { status: 400  );
     console.error('Update user error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
}
}
}