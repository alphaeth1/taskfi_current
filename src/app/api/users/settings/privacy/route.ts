import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });;
     const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: {
        privacySettings: true,
      },
    });

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
     // Default privacy settings if none exist
    const defaultSettings = {
      profileVisibility: 'public',
      earningsVisibility: 'private',
      reviewsVisibility: 'public',
      allowDirectMessages: true,
      showOnlineStatus: true,
      searchEngineIndexing: true,
      dataSharing: false,
    };

    const settings = user.privacySettings || defaultSettings;

    return NextResponse.json(settings);
    } catch (error) {
    console.error('Error fetching privacy settings:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   export async function PUT(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });;
     const body = await request.json();
    const {
      profileVisibility,
      earningsVisibility,
      reviewsVisibility,
      allowDirectMessages,
      showOnlineStatus,
      searchEngineIndexing,
      dataSharing,
    } = body;

    // Validate privacy settings
    const validVisibilityOptions = ['public', 'private', 'connections'];
    
    if (profileVisibility && !validVisibilityOptions.includes(profileVisibility)) {
      return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     if (earningsVisibility && !['public', 'private'].includes(earningsVisibility)) {
      return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     if (reviewsVisibility && !validVisibilityOptions.includes(reviewsVisibility)) {
      return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     const updatedUser = await prisma.user.update({
      where: { id: session.user.id },
      data: {
        privacySettings: {
          profileVisibility: profileVisibility || 'public',
          earningsVisibility: earningsVisibility || 'private',
          reviewsVisibility: reviewsVisibility || 'public',
          allowDirectMessages: allowDirectMessages !== false,
          showOnlineStatus: showOnlineStatus !== false,
          searchEngineIndexing: searchEngineIndexing !== false,
          dataSharing: dataSharing || false,
        },
      },
      select: {
        privacySettings: true,
      },
    });

    return NextResponse.json({
      message: 'Privacy settings updated successfully',
      settings: updatedUser.privacySettings,
    });
  } catch (error) {
    console.error('Error updating privacy settings:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }


}
}}}
}