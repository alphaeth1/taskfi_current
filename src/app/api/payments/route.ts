import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, PermissionService } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'

const getPaymentsQuerySchema = z.object({
  status: z.enum(['PENDING', 'ESCROW', 'RELEASED', 'REFUNDED', 'DISPUTED']).optional(),
  type: z.enum(['job', 'gig']).optional(),
  page: z.string().default('1'),
  limit: z.string().default('10'),
  sortBy: z.enum(['createdAt', 'amount', 'status']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
})

const createPaymentSchema = z.object({
  amount: z.number().min(1).max(1000000),
  currency: z.enum(['USDC', 'SOL']).default('USDC'),
  jobId: z.string().optional(),
  gigId: z.string().optional(),
  packageDetails: z.any().optional(),
})

// GET /api/payments - Get user's payments
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     const { searchParams } = new URL(request.url)
    const query = getPaymentsQuerySchema.parse({
      status: searchParams.get('status'),
      type: searchParams.get('type'),
      page: searchParams.get('page'),
      limit: searchParams.get('limit'),
      sortBy: searchParams.get('sortBy'),
      sortOrder: searchParams.get('sortOrder'),
    })

    const page = parseInt(query.page)
    const limit = Math.min(parseInt(query.limit), 50)
    const skip = (page - 1) * limit

    const where: any = {
      payerId: session.user.id
     if (query.status) {
      where.status = query.status
     if (query.type === 'job') {
      where.jobId = { not: null  } else if (query.type === 'gig') {
      where.gigId = { not:}
 null }
    }

    const orderBy: any = {}
    orderBy[query.sortBy] = query.sortOrder

    const [payments, total] = await Promise.all([
      prisma.payment.findMany({
        where,
        include: {
          payer: {
            select: {
              id: true,
              name: true,
              username: true,
              avatarUrl: true,
            },
          },
          job: {
            select: {
              id: true,
              title: true,
              status: true,
              freelancer: {
                select: {
                  id: true,
                  name: true,
                  username: true,
                  avatarUrl: true,
                }
               },
          },
          gig: {
            select: {
              id: true,
              title: true,
              status: true,
              freelancer: {
                select: {
                  id: true,
                  name: true,
                  username: true,
                  avatarUrl: true,
                 },
          },
        },
        skip,
        take: limit,
        orderBy,
      }),
      prisma.payment.count({ where }),
    ])

    // Calculate payment statistics
    const stats = {
      total: payments.length,
      pending: payments.filter(p => p.status === 'PENDING').length,
      escrow: payments.filter(p => p.status === 'ESCROW').length,
      released: payments.filter(p => p.status === 'RELEASED').length,
      disputed: payments.filter(p => p.status === 'DISPUTED').length,
      totalAmount: payments.reduce((sum, p) => sum + p.amount, 0),
      totalInEscrow: payments.filter(p => p.status === 'ESCROW').reduce((sum, p) => sum + p.amount, 0),
     return NextResponse.json({
      payments,
      stats,
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
     console.error('Get payments error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // POST /api/payments - Create payment (for manual escrow funding)
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
    }

    const body = await request.json()
    const paymentData = createPaymentSchema.parse(body)

    // Validate that either jobId or gigId is provided
    if (!paymentData.jobId && !paymentData.gigId) {
      return NextResponse.json({ error: "Internal server}
 error" }, { status: 400 });
    }

    if (paymentData.jobId && paymentData.gigId) {
      return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     // Verify job or gig exists and user can pay for it
    if (paymentData.jobId) {
      const job = await prisma.job.findUnique({
        where: { id: paymentData.jobId },
        select: { hirerId: true, status: true, freelancerId: true },
      })

      if (!job) {
        return NextResponse.json({ error: 'Job not}
 found' }, { status: 404 })
       if (job.hirerId !== session.user.id) {
        return NextResponse.json({ error: 'Can only pay for your own jobs' }, { status: 403 })
       if (job.status !== 'IN_PROGRESS') {
        return NextResponse.json({ error: 'Job must be in progress to create payment' }, { status: 400 });
       if (!job.freelancerId) {
        return NextResponse.json({ error: 'Job must have an assigned freelancer' }, { status: 400 });
      }
     if (paymentData.gigId) {
      const gig = await prisma.gig.findUnique({
        where: { id: paymentData.gigId },
        select: { freelancerId: true, status: true },
      })

      if (!gig) {
        return NextResponse.json({ error: 'Gig not found' }, { status: 404 });
       if (gig.status !== 'ACTIVE') {
        return NextResponse.json({ error: 'Gig must be active to create payment' }, { status: 400 });
       if (gig.freelancerId === session.user.id) {
        return NextResponse.json({ error: 'Cannot pay for your own gig' }, { status: 400 });
       // Create payment in escrow status
    const payment = await prisma.payment.create({
      data: {
        ...paymentData,
        payerId: session.user.id,
        status: 'ESCROW', // Funds go directly to escrow
        packageDetails: paymentData.packageDetails || null,
      },
      include: {
        payer: {
          select: {
            id: true,
            name: true,
            username: true,
            avatarUrl: true,
          },
        },
        job: paymentData.jobId ? {
          select: {
            id: true,
            title: true,
            freelancer: {
              select: {
                id: true,
                name: true,
                username: true,
              }
             },
        } : undefined,
        gig: paymentData.gigId ? {
          select: {
            id: true,
            title: true,
            freelancer: {
              select: {
                id: true,
                name: true,
                username: true,
               },
        } : undefined,
      },
    })

    return NextResponse.json({ payment }, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Validation error', details: error.errors },
        { status: 400  );
     console.error('Create payment error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}


}
}}}}}}
}}}}}