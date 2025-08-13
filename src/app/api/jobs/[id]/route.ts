import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, PermissionService } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'

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


// GET /api/jobs/[id] - Get job details
export async function GET(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    try {
    const session = await getServerSession(authOptions);
    
    const job = await prisma.job.findUnique({
      where: { id: params.id },
      include: {
        hirer: {
          select: {
            id: true,
            name: true,
            username: true,
            avatarUrl: true,
            rating: true,
            isVerified: true,
            totalSpent: true,
            createdAt: true,
          },
        },
        category: {
          select: {
            id: true,
            name: true,
            icon: true,
          },
        },
        applications: {
          include: {
            freelancer: {
              select: {
                id: true,
                name: true,
                username: true,
                avatarUrl: true,
                rating: true,
                isVerified: true,
                categories: true,
              },
            },
          },
          orderBy: { createdAt: 'desc' },
        },
        payments: {
          select: {
            id: true,
            amount: true,
            status: true,
            createdAt: true,
          },
        },
        messages: session ? {
          where: {
            OR: [
              { senderId: session.user.id },
              { receiverId: session.user.id },
            ],
          },
          select: {
            id: true,
            content: true,
            type: true,
            senderId: true,
            isRead: true,
            createdAt: true,
          },
          orderBy: { createdAt: 'asc' },
        } : false,
        reviews: {
          where: { isPublic: true },
          include: {
            author: {
              select: {
                name: true,
                username: true,
                avatarUrl: true,
              },
            },
          },
        },
      },
    })

    if (!job) {
      return NextResponse.json({ error: 'Job not found' }, { status: 404 })
    // Increment view count
    await prisma.job.update({
      where: { id: params.id },
      data: { viewCount: { increment: 1 } },
    })

    // Hide sensitive application data if not authorized
    if (!session || (session.user.id !== job.hirerId && !PermissionService.canAccessUserManagement(session.user.role))) {
      job.applications = job.applications.map(app => ({
        ...app,
        coverLetter: '',
        proposedBudget: 0,
        estimatedDays: 0,
        attachments: [],
      }))
    return NextResponse.json({ job });
  } catch (error) {
    console.error('Get job error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // PUT /api/jobs/[id] - Update job
export async function PUT(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     const body = await request.json()
    const updateData = updateJobSchema.parse(body)

    // Check if user owns the job or is admin
    const job = await prisma.job.findUnique({
      where: { id: params.id },
      select: { hirerId: true, status: true },
    })

    if (!job) {
      return NextResponse.json({ error: 'Job not found' }, { status: 404 })
     const canUpdate = job.hirerId === session.user.id || 
                     PermissionService.canAccessUserManagement(session.user.role)

    if (!canUpdate) {
      return NextResponse.json({ error: 'Forbidden'  }, { status: 403 });
    }
    // Validate category if provided
    if (updateData.categoryId) {
      const category = await prisma.category.findUnique({
        where: { id:}
 updateData.categoryId },
      })

      if (!category || !category.isActive) {
        return NextResponse.json({ error: "Invalid}
 category" }, { status: 400 });
       const updatedJob = await prisma.job.update({
      where: { id: params.id },
      data: {
        ...updateData,
        deadline: updateData.deadline ? new Date(updateData.deadline) : undefined,
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

    return NextResponse.json({ job: updatedJob });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: "Invalid job data" }, { status: 400 });
     console.error('Update job error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // DELETE /api/jobs/[id] - Delete job
export async function DELETE(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     // Check if user owns the job or is admin
    const job = await prisma.job.findUnique({
      where: { id: params.id },
      select: { 
        hirerId: true, 
        status: true,
        _count: {
          select: {
            applications: true,
            payments: true,
          },
        },
      },
    })

    if (!job) {
      return NextResponse.json({ error: 'Job not found' }, { status: 404 })
     const canDelete = job.hirerId === session.user.id || 
                     PermissionService.canAccessUserManagement(session.user.role)

    if (!canDelete) {
      return NextResponse.json({ error: 'Forbidden'  }, { status: 403 });
     // Don't allow deletion if job has applications or payments
    if (job._count.applications > 0 || job._count.payments > 0) {
      return NextResponse.json({ error: "Cannot delete job with applications or payments" }, { status: 400 });
     // Only allow deletion if job is still OPEN
    if (job.status !== 'OPEN') {
      return NextResponse.json({ error: "Can only delete open jobs" }, { status: 400 });
     await prisma.job.delete({
      where: { id: params.id },
    })

    return NextResponse.json({ message: 'Job deleted successfully' });
  } catch (error) {
    console.error('Delete job error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }


}
}
}}}
}