import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, PermissionService } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'

const createApplicationSchema = z.object({
  coverLetter: z.string().min(50).max(2000),
  proposedBudget: z.number().min(1).max(1000000),
  estimatedDays: z.number().min(1).max(365),
  attachments: z.array(z.string()).max(5).default([]),
})

const updateApplicationSchema = z.object({
  isAccepted: z.boolean(),
})


// GET /api/jobs/[id]/applications - Get all applications for a job
export async function GET(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    try {
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
    // Verify job exists
    const job = await prisma.job.findUnique({
      where: { id: params.id },
      select: { hirerId: true, status: true  })

    if (!job) {
      return NextResponse.json({ error: 'Job not found' }, { status: 404 })
    // Only job owner, applicants, or admins can view applications
    const canViewApplications = 
      job.hirerId === session.user.id || 
      PermissionService.canAccessUserManagement(session.user.role)

    if (!canViewApplications) {
      // Check if user has applied to this job
      const userApplication = await prisma.jobApplication.findUnique({
        where: {
          freelancerId_jobId: {
            freelancerId: session.user.id,
            jobId: params.id
           })

      if (!userApplication) {
        return NextResponse.json({ error: 'Forbidden'  }, { status: 403 });
      // Return only user's own application
      const application = await prisma.jobApplication.findUnique({
        where: { id: userApplication.id },
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
        },
      })

      return NextResponse.json({ applications: [application] })
    // Job owner or admin - return all applications
    const applications = await prisma.jobApplication.findMany({
      where: { jobId: params.id },
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
      },
      orderBy: [
        { isAccepted: 'desc' }, // Accepted first
        { createdAt: 'asc' }    // Then by earliest
      ],
    })

    const stats = {
      total: applications.length,
      pending: applications.filter(app => app.isAccepted === null).length,
      accepted: applications.filter(app => app.isAccepted === true).length,
      rejected: applications.filter(app => app.isAccepted === false).length,
      averageProposedBudget: applications.length > 0 
        ? applications.reduce((sum, app) => sum + app.proposedBudget, 0) / applications.length 
        : 0,
      averageEstimatedDays: applications.length > 0
        ? applications.reduce((sum, app) => sum + app.estimatedDays, 0) / applications.length
        : 0,
     return NextResponse.json({ applications, stats });
  } catch (error) {
    console.error('Get applications error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // POST /api/jobs/[id]/applications - Apply to a job
export async function POST(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     // Only freelancers can apply
    if (!PermissionService.canApplyToJobs(session.user.role)) {
      return NextResponse.json({ error: 'Only freelancers can apply to jobs' }, { status: 403 });
     const body = await request.json()
    const applicationData = createApplicationSchema.parse(body)

    // Verify job exists and is open
    const job = await prisma.job.findUnique({
      where: { id: params.id },
      select: { 
        id: true,
        hirerId: true, 
        status: true, 
        budget: true,
        title: true,
        applications: {
          where: { isAccepted: true },
          take: 1
         })

    if (!job) {
      return NextResponse.json({ error: 'Job not found' }, { status: 404 })
     if (job.status !== 'OPEN') {
      return NextResponse.json({ error: 'Job is no longer accepting applications' }, { status: 400 });
     // Can't apply to own job
    if (job.hirerId === session.user.id) {
      return NextResponse.json({ error: 'Cannot apply to your own job' }, { status: 400 });
     // Check if job already has an accepted application (exclusive hiring)
    if (job.applications.length > 0) {
      return NextResponse.json({ error: 'This job has already been filled' }, { status: 400 });
    }
    
    // Validate proposed budget is reasonable (within 20% above job budget)
    if (applicationData.proposedBudget > job.budget * 1.2) {
      return NextResponse.json({ 
        error: `Proposed budget cannot exceed ${(job.budget * 1.2).toFixed(2)}` 
      }, { status: 400 })
     // Check if user already applied
    const existingApplication = await prisma.jobApplication.findUnique({
      where: {
        freelancerId_jobId: {
          freelancerId: session.user.id,
          jobId: params.id
         })

    if (existingApplication) {
      return NextResponse.json({ error: 'You have already applied to this job' }, { status: 400 });
    }
    // Create application
    const application = await prisma.jobApplication.create({
      data: {
        ...applicationData,
        freelancerId: session.user.id,
        jobId: params.id,
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
          },
        },
        job: {
          select: {
            id: true,
            title: true,
            budget: true,
            hirer: {
              select: {
                id: true,
                name: true,
                username: true,
               },
    })

    // Create notification for job owner
    await prisma.notification.create({
      data: {
        userId: job.hirerId,
        type: 'JOB_APPLICATION',
        title: 'New Job Application',
        message: `${session.user.name} applied to your job: ${job.title}`,
        data: {
          jobId: job.id,
          applicationId: application.id,
          freelancerId: session.user.id
         })

    return NextResponse.json({ application }, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: "Invalid application data" }, { status: 400 });
     console.error('Create application error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // PUT /api/jobs/[id]/applications - Accept or reject applications (batch or single);
export async function PUT(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     const body = await request.json()
    
    // Handle batch updates (for accepting one and rejecting others)
    if (body.applications && Array.isArray(body.applications)) {
      // Verify job ownership
      const job = await prisma.job.findUnique({
        where: { id: params.id },
        select: { 
          hirerId: true, 
          status: true,
          title: true,
          applications: {
            where: { isAccepted: true },
            take: 1
           })

      if (!job) {
        return NextResponse.json({ error: 'Job not found' }, { status: 404 })
       const canUpdate = job.hirerId === session.user.id || 
                       PermissionService.canAccessUserManagement(session.user.role)

      if (!canUpdate) {
        return NextResponse.json({ error: 'Forbidden'  }, { status: 403 });
       if (job.status !== 'OPEN') {
        return NextResponse.json({ error: 'Cannot update applications for non-open jobs' }, { status: 400 });
       // Check if job already has accepted application
      if (job.applications.length > 0) {
        return NextResponse.json({ error: 'This job already has an accepted freelancer' }, { status: 400 });
       // Validate applications array
      const acceptedCount = body.applications.filter(app => app.isAccepted === true).length
      if (acceptedCount > 1) {
        return NextResponse.json({ error: 'Can only accept one application per job' }, { status: 400 });
       if (acceptedCount === 0) {
        return NextResponse.json({ error: 'Must accept at least one application' }, { status: 400 });
       // Update applications in transaction
      const updatedApplications = await prisma.$transaction(async (tx) => {
        const updates = []
        
        for (const appUpdate of body.applications) {
          const updated = await tx.jobApplication.update({
            where: { 
              id: appUpdate.id,
              jobId: params.id // Ensure application belongs to this job
            },
            data: { isAccepted: appUpdate.isAccepted },
            include: {
              freelancer: {
                select: {
                  id: true,
                  name: true,
                  username: true,
                  avatarUrl: true,
                 })
          updates.push(updated)

          // Create notification for freelancer
          await tx.notification.create({
            data: {
              userId: updated.freelancerId,
              type: appUpdate.isAccepted ? 'APPLICATION_ACCEPTED' : 'APPLICATION_REJECTED',
              title: appUpdate.isAccepted ? 'Application Accepted!' : 'Application Update',
              message: appUpdate.isAccepted 
                ? `Congratulations! Your application for "${job.title}" has been accepted.`
                : `Your application for "${job.title}" was not selected this time.`,
              data: {
                jobId: params.id,
                applicationId: updated.id,
                isAccepted: appUpdate.isAccepted
               })
         // If there's an accepted application, update job status
        const acceptedApp = updates.find(app => app.isAccepted === true)
        if (acceptedApp) {
          await tx.job.update({
            where: { id: params.id },
            data: { 
              status: 'IN_PROGRESS',
              freelancerId: acceptedApp.freelancerId
            }
          })
        }
        
        return updates
      })

      return NextResponse.json({ applications: updatedApplications });
    }
    
    // Handle single application update
    const { applicationId, isAccepted } = updateApplicationSchema.parse(body)
    
    // Verify job ownership and application exists
    const application = await prisma.jobApplication.findFirst({
      where: { 
        id: applicationId,
        jobId: params.id 
      },
      include: {
        job: {
          select: {
            hirerId: true,
            status: true,
            title: true,
            applications: {
              where: { isAccepted: true },
              take: 1
             },
        freelancer: {
          select: {
            id: true,
            name: true,
            username: true,
           })

    if (!application) {
      return NextResponse.json({ error: 'Application not}
 found' }, { status: 404 })
     const canUpdate = application.job.hirerId === session.user.id || 
                     PermissionService.canAccessUserManagement(session.user.role)

    if (!canUpdate) {
      return NextResponse.json({ error: 'Forbidden'  }, { status: 403 });
     if (application.job.status !== 'OPEN') {
      return NextResponse.json({ error: 'Cannot update applications for non-open jobs' }, { status: 400 });
     // If accepting and job already has accepted application
    if (isAccepted && application.job.applications.length > 0) {
      return NextResponse.json({ error: 'This job already has an accepted freelancer' }, { status: 400 });
     // Update application
    const updatedApplication = await prisma.$transaction(async (tx) => {
      const updated = await tx.jobApplication.update({
        where: { id: applicationId },
        data: { isAccepted },
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

      // Create notification
      await tx.notification.create({
        data: {
          userId: updated.freelancerId,
          type: isAccepted ? 'APPLICATION_ACCEPTED' : 'APPLICATION_REJECTED',
          title: isAccepted ? 'Application Accepted!' : 'Application Update',
          message: isAccepted 
            ? `Congratulations! Your application for "${application.job.title}" has been accepted.`
            : `Your application for "${application.job.title}" was not selected this time.`,
          data: {
            jobId: params.id,
            applicationId: updated.id,
            isAccepted
           })

      // If accepted, update job status and reject other applications
      if (isAccepted) {
        await tx.job.update({
          where: { id: params.id },
          data: { 
            status: 'IN_PROGRESS',
            freelancerId: updated.freelancerId
           })

        // Reject all other applications
        await tx.jobApplication.updateMany({
          where: {
            jobId: params.id,
            id: { not: applicationId },
            isAccepted: null
          },
          data: { isAccepted: false  })
       return updated
    })

    return NextResponse.json({ application: updatedApplication });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Validation error', details: error.errors },
        { status: 400  );
     console.error('Update application error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
}}}}}
}}}}}}}}}}}}
}}}}}}}}
}}}}}
}}}