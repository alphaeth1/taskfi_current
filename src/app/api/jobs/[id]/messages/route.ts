import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { PrismaClient } from '@prisma/client';
import Pusher from 'pusher';

const prisma = new PrismaClient();

const pusher = new Pusher({
  appId: process.env.PUSHER_APP_ID!,
  key: process.env.PUSHER_KEY!,
  secret: process.env.PUSHER_SECRET!,
  cluster: process.env.PUSHER_CLUSTER!,
  useTLS: true,
});

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string }  ) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });;
     const jobId = params.id;
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = (page - 1) * limit;

    // Check if user has access to this job conversation
    const job = await prisma.job.findUnique({
      where: { id: jobId },
      include: {
        hirer: true,
        applications: {
          where: { isAccepted: true },
          include: { freelancer: true },
        },
      },
    });

    if (!job) {
      return NextResponse.json({ error: 'Job not found' }, { status: 404 });
     // User must be either the hirer or the accepted freelancer
    const isHirer = job.hirerId === session.user.id;
    const acceptedFreelancer = job.applications.find(app => app.isAccepted);
    const isAcceptedFreelancer = acceptedFreelancer?.freelancerId === session.user.id;

    if (!isHirer && !isAcceptedFreelancer) {
      return NextResponse.json({ error: 'Access denied' }, { status: 403 });
     // Get messages for this job
    const messages = await prisma.message.findMany({
      where: { jobId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
      include: {
        sender: {
          select: {
            id: true,
            name: true,
            username: true,
            avatarUrl: true,
          },
        },
      },
    });

    // Mark messages as read if they're sent to current user
    await prisma.message.updateMany({
      where: {
        jobId,
        receiverId: session.user.id,
        isRead: false,
      },
      data: {
        isRead: true,
      },
    });

    return NextResponse.json({
      messages: messages.reverse(), // Return in chronological order
      job: {
        id: job.id,
        title: job.title,
        hirer: {
          id: job.hirer.id,
          name: job.hirer.name,
          username: job.hirer.username,
          avatarUrl: job.hirer.avatarUrl,
        },
        freelancer: acceptedFreelancer ? {
          id: acceptedFreelancer.freelancer.id,
          name: acceptedFreelancer.freelancer.name,
          username: acceptedFreelancer.freelancer.username,
          avatarUrl: acceptedFreelancer.freelancer.avatarUrl,
        } : null,
      },
      hasMore: messages.length === limit,
      currentPage: page,
    });
    } catch (error) {
    console.error('Error fetching messages:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   export async function POST(
  request: NextRequest,
  { params }: { params: { id: string }  ) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });;
     const jobId = params.id;
    const body = await request.json();
    const { content, type = 'TEXT', fileUrl } = body;

    if (!content && !fileUrl) {
      return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     // Check if user has access to this job conversation
    const job = await prisma.job.findUnique({
      where: { id: jobId },
      include: {
        applications: {
          where: { isAccepted: true },
        },
      },
    });

    if (!job) {
      return NextResponse.json({ error: 'Job not found' }, { status: 404 });
     const isHirer = job.hirerId === session.user.id;
    const acceptedFreelancer = job.applications.find(app => app.isAccepted);
    const isAcceptedFreelancer = acceptedFreelancer?.freelancerId === session.user.id;

    if (!isHirer && !isAcceptedFreelancer) {
      return NextResponse.json({ error: 'Access denied' }, { status: 403 });
     // Determine receiver (the other party in the conversation)
    let receiverId: string;
    if (isHirer) {
      if (!acceptedFreelancer) {
        return NextResponse.json({ error: "Internal server error" }, { status: 400 });
       receiverId = acceptedFreelancer.freelancerId;
    } else {
      receiverId = job.hirerId;
     // Create the message
    const message = await prisma.message.create({
      data: {
        content: content || '',
        type,
        fileUrl,
        senderId: session.user.id,
        receiverId,
        jobId,
      },
      include: {
        sender: {
          select: {
            id: true,
            name: true,
            username: true,
            avatarUrl: true,
          },
        },
      },
    });

    // Send real-time notification via Pusher
    await pusher.trigger(`job-${jobId}`, 'new-message', {
      message,
      senderId: session.user.id,
      receiverId,
    });

    // Create notification for receiver
    await prisma.notification.create({
      data: {
        title: 'New Message',
        message: `${message.sender.name} sent you a message about "${job.title}"`,
        type: 'message',
        userId: receiverId,
        actionUrl: `/jobs/${jobId}/chat`,
        metadata: {
          jobId,
          messageId: message.id,
          senderId: session.user.id,
        },
      },
    });

    return NextResponse.json({
      message,
      success: true,
    });
  } catch (error) {
    console.error('Error sending message:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }


}
}
}}
}}
}
}