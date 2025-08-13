import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, PermissionService } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'

const updateApplicationSchema = z.object({
  coverLetter: z.string().min(50).max(2000).optional(),
  proposedBudget: z.number().min(1).max(1000000).optional(),
  estimatedDays: z.number().min(1).max(365).optional(),
  attachments: z.array(z.string()).max(5).optional(),
})


// GET /api/jobs/[id]/applications/[applicationId] - Get specific application
export async function GET(request: NextRequest, props: { params: Promise<{ id: string; applicationId: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     const application = await prisma.jobApplication.findFirst({
      where: { 
        id: params.applicationId,
        jobId: params.id 
      },
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
            totalEarned: true,
            completedJobs: true,
            createdAt: true,
          },
        },
        job: {
          select: {
            id: true,
            title: true,
            budget: true,
            status: true,
            hirerId: true,
            hirer: {
              select: {
                id: true,
                name: true,
                username: true,
                avatarUrl: true,
               },
            },
          },
        },
      }

    if (!application) {
      return NextResponse.json({ error: 'Application not found' }, { status: 404 })
     // Check permissions - job owner, applicant, or admin
    const canView = 
      application.job.hirerId === session.user.id || 
      application.freelancerId === session.user.id ||
      PermissionService.canAccessUserManagement(session.user.role)

    if (!canView) {
      return NextResponse.json({ error: 'Forbidden'  }, { status: 403 });
     // Hide sensitive data for non-owners
    if (application.job.hirerId !== session.user.id && !PermissionService.canAccessUserManagement(session.user.role)) {
      const { coverLetter, proposedBudget, estimatedDays, attachments, ...publicData } = application
      return NextResponse.json({ application: publicData });
     return NextResponse.json({ application });
  } catch (error) {
    console.error('Get application error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // PUT /api/jobs/[id]/applications/[applicationId] - Update application (freelancer only)
export async function PUT(request: NextRequest, props: { params: Promise<{ id: string; applicationId: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     const body = await request.json()
    const updateData = updateApplicationSchema.parse(body)

    // Find application and verify ownership
    const application = await prisma.jobApplication.findFirst({
      where: { 
        id: params.applicationId,
        jobId: params.id 
      },
      include: {
        job: {
          select: {
            status: true,
            budget: true,
            title: true,
           })

    if (!application) {
      return NextResponse.json({ error: 'Application not found' }, { status: 404 })
     // Only the applicant can update their own application
    if (application.freelancerId !== session.user.id) {
      return NextResponse.json({ error: 'Can only update your own applications' }, { status: 403 })
     // Can only update pending applications
    if (application.isAccepted !== null) {
      return NextResponse.json({ 
        error: 'Cannot update application that has already been processed' 
      }, { status: 400 })
     // Can only update applications for open jobs
    if (application.job.status !== 'OPEN') {
      return NextResponse.json({ 
        error: 'Cannot update application for non-open jobs' 
      }, { status: 400 });
    }
    
    // Validate proposed budget if provided
    if (updateData.proposedBudget && updateData.proposedBudget > application.job.budget * 1.2) {
      return NextResponse.json({ 
        error: `Proposed budget cannot}
 exceed ${(application.job.budget * 1.2).toFixed(2)}` 
      }, { status: 400 })
    }
    const updatedApplication = await prisma.jobApplication.update({
      where: { id: params.applicationId },
      data: updateData,
      include: {
        freelancer: {
          select: {
            id: true,
            name: true,
            username: true,
            avatarUrl: true,
            rating: true,
            isVerified: true,
           })

    return NextResponse.json({ application: updatedApplication });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: "Invalid application data" }, { status: 400 });
     console.error('Update application error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // DELETE /api/jobs/[id]/applications/[applicationId] - Withdraw application
export async function DELETE(request: NextRequest, props: { params: Promise<{ id: string; applicationId: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     // Find application and verify ownership
    const application = await prisma.jobApplication.findFirst({
      where: { 
        id: params.applicationId,
        jobId: params.id 
      },
      include: {
        job: {
          select: {
            status: true,
            title: true,
            hirerId: true,
           })

    if (!application) {
      return NextResponse.json({ error: 'Application not found' }, { status: 404 })
     // Only the applicant or admin can delete the application
    const canDelete = 
      application.freelancerId === session.user.id || 
      PermissionService.canAccessUserManagement(session.user.role)

    if (!canDelete) {
      return NextResponse.json({ error: 'Forbidden'  }, { status: 403 });
     // Cannot withdraw accepted applications
    if (application.isAccepted === true) {
      return NextResponse.json({ 
        error: 'Cannot withdraw accepted application. Contact the hirer to discuss.' 
      }, { status: 400 });
     // Delete the application
    await prisma.$transaction(async (tx) => {
      await tx.jobApplication.delete({
        where: { id: params.applicationId  })

      // Notify job owner if application was withdrawn (not rejected)
      if (application.isAccepted === null && application.freelancerId === session.user.id) {
        await tx.notification.create({
          data: {
            userId: application.job.hirerId,
            type: 'APPLICATION_WITHDRAWN',
            title: 'Application Withdrawn',
            message: `${session.user.name} withdrew their application for "${application.job.title}"`,
            data: {
              jobId: params.id,
              applicationId: params.applicationId,
              freelancerId: session.user.id
             })
       })

    return NextResponse.json({ message: 'Application withdrawn successfully' });
  } catch (error) {
    console.error('Delete application error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
}}
}}}
}}}
}}
}