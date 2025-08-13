import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string }  ) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });;
     const jobId = params.id;

    // Check if job exists
    const job = await prisma.job.findUnique({
      where: { id: jobId },
      select: { id: true, hirerId: true, views: true },
    });

    if (!job) {
      return NextResponse.json({ error: 'Job not found' }, { status: 404 });
     // Don't count views from the job hirer themselves
    if (job.hirerId === session.user.id) {
      return NextResponse.json({ 
        message: 'View not counted for job owner',
        views: job.views 
      });
     // Check if user has already viewed this job in the last 24 hours
    const recentView = await prisma.jobView.findFirst({
      where: {
        jobId: jobId,
        userId: session.user.id,
        viewedAt: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // 24 hours ago
        },
      },
    });

    if (recentView) {
      return NextResponse.json({ 
        message: 'View already counted recently',
        views: job.views 
      });
     // Record the view and increment the counter
    await prisma.$transaction([
      // Create view record
      prisma.jobView.create({
        data: {
          jobId: jobId,
          userId: session.user.id,
          viewedAt: new Date(),
        },
      }),
      // Increment view count
      prisma.job.update({
        where: { id: jobId },
        data: {
          views: {
            increment: 1,
          },
        },
      }),
    ]);

    const updatedJob = await prisma.job.findUnique({
      where: { id: jobId },
      select: { views: true },
    });

    return NextResponse.json({
      message: 'View recorded successfully',
      views: updatedJob?.views || job.views + 1,
    });
  } catch (error) {
    console.error('Error recording job view:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }


}
}}
}}}