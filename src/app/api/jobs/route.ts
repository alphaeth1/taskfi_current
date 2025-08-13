import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, PermissionService } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'

const createJobSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().min(10).max(5000),
  requirements: z.array(z.string()).min(1).max(10),
  budget: z.number().min(1).max(1000000),
  deadline: z.string().datetime().optional(),
  isUrgent: z.boolean().default(false),
  attachments: z.array(z.string()).max(5).default([]),
  tags: z.array(z.string()).max(10).default([]),
  categoryId: z.string(),
})

const updateJobSchema = z.object({
  title: z.string().min(1).max(200).optional(),
  description: z.string().min(10).max(5000).optional(),
  requirements: z.array(z.string()).min(1).max(10).optional(),
  budget: z.number().min(1).max(1000000).optional(),
  deadline: z.string().datetime().optional(),
  isUrgent: z.boolean().optional(),
  attachments: z.array(z.string()).max(5).optional(),
  tags: z.array(z.string()).max(10).optional(),
  categoryId: z.string().optional(),
  status: z.enum(['OPEN', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'DISPUTED']).optional(),
})

const getJobsQuerySchema = z.object({
  category: z.string().optional(),
  minBudget: z.string().optional(),
  maxBudget: z.string().optional(),
  search: z.string().optional(),
  status: z.string().optional(),
  urgent: z.string().optional(),
  page: z.string().default('1'),
  limit: z.string().default('10'),
  sortBy: z.enum(['createdAt', 'budget', 'deadline']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
})

// GET /api/jobs - Get jobs with filtering and pagination
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const query = getJobsQuerySchema.parse({
      category: searchParams.get('category'),
      minBudget: searchParams.get('minBudget'),
      maxBudget: searchParams.get('maxBudget'),
      search: searchParams.get('search'),
      status: searchParams.get('status'),
      urgent: searchParams.get('urgent'),
      page: searchParams.get('page'),
      limit: searchParams.get('limit'),
      sortBy: searchParams.get('sortBy'),
      sortOrder: searchParams.get('sortOrder'),
    })

    const page = parseInt(query.page)
    const limit = Math.min(parseInt(query.limit), 50)
    const skip = (page - 1) * limit

    const where: any = {}

    if (query.category) {
      where.categoryId = query.category
    }

    if (query.minBudget || query.maxBudget) {
     }
 where.budget = { if (query.minBudget) where.budget.gte = parseFloat(query.minBudget)
      if (query.maxBudget) where.budget.lte = parseFloat(query.maxBudget)
     if (query.search) {
      where.OR = [
        { title: { contains: query.search, mode: 'insensitive' } },
        { description: { contains: query.search, mode: 'insensitive' } },
        { tags: { has: query.search } },
      ]
     if (query.status) {
      where.status = query.status
    } else {
      where.status = 'OPEN' // Default to open jobs
     if (query.urgent === 'true') {
      where.isUrgent = true
    }

    const orderBy: any = { orderBy[query.sortBy] = query.sortOrder

    const [jobs, total] = await Promise.all([
      prisma.job.findMany({
        where,
        include: {
          hirer: {
            select: {
              id: true,
              name: true,
              username: true,
              avatarUrl: true,
              rating: true,
              isVerified: true,
            },
          },
          category: {
            select: {
              id: true,
              name: true,
              icon: true,
            },
          },
          _count: {
            select: {
              applications: true,
            },
          },
        },
        skip,
        take: limit,
        orderBy,
      }),
      prisma.job.count({ where }),
    ])

    return NextResponse.json({
      jobs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
    } catch (error) {
    if (error instanceof z.ZodError) {
    return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     console.error('Get jobs error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // POST /api/jobs - Create new job (hirer only)
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     if (!PermissionService.canPostJobs(session.user.role)) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
     const body = await request.json()
    const jobData = createJobSchema.parse(body)

    // Verify category exists
    const category = await prisma.category.findUnique({
      where: { id: jobData.categoryId },
    })

    if (!category || !category.isActive) {
      return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     const job = await prisma.job.create({
      data: {
        ...jobData,
        deadline: jobData.deadline ? new Date(jobData.deadline) : null,
        hirerId: session.user.id,
      },
      include: {
        hirer: {
          select: {
            id: true,
            name: true,
            username: true,
            avatarUrl: true,
            rating: true,
            isVerified: true,
          },
        },
        category: {
          select: {
            id: true,
            name: true,
            icon: true,
          },
        },
      },
    })

    return NextResponse.json({ job }, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Validation error', details: error.errors },
        { status: 400  );
     console.error('Create job error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}


}
}}
}}