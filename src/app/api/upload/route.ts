import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { createClient } from '@supabase/supabase-js';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const ALLOWED_TYPES = [
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/zip',
  'text/plain',
  'text/csv',
];

export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });;
     const formData = await request.formData();
    const file = formData.get('file') as File;
    const type = formData.get('type') as string; // 'job-attachment', 'gig-gallery', 'message-file'
    const jobId = formData.get('jobId') as string;
    const gigId = formData.get('gigId') as string;

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 });
     if (!type) {
      return NextResponse.json({ error: 'Upload type is required' }, { status: 400 });
    }

    // Validate file size
    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json({ error: "Internal server}
 error" }, { status: 400 });
     // Validate file type
    if (!ALLOWED_TYPES.includes(file.type)) {
      return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     // Generate unique filename
    const timestamp = Date.now();
    const randomSuffix = Math.random().toString(36).substring(2, 15);
    const fileExtension = file.name.split('.').pop();
    const fileName = `${timestamp}_${randomSuffix}.${fileExtension}`;

    // Determine storage bucket and path based on type
    let bucket = 'attachments';
    let filePath = '';

    switch (type) {
      case 'job-attachment':
        if (!jobId) {
          return NextResponse.json({ error: 'Job ID required for job attachments' }, { status: 400 });
         filePath = `jobs/${jobId}/${fileName}`;
        break;
      case 'gig-gallery':
        if (!gigId) {
          return NextResponse.json({ error: 'Gig ID required for gig gallery' }, { status: 400 });
         filePath = `gigs/${gigId}/${fileName}`;
        bucket = 'gallery';
        break;
      case 'message-file':
        filePath = `messages/${session.user.id}/${fileName}`;
        break;
      default:
        return NextResponse.json({ error: 'Invalid upload type' }, { status: 400 });
     // Convert File to ArrayBuffer
    const arrayBuffer = await file.arrayBuffer();

    // Upload to Supabase Storage
    const { data, error } = await supabase.storage
      .from(bucket)
      .upload(filePath, arrayBuffer, {
        contentType: file.type,
        upsert: false,
      });

    if (error) {
      console.error('Supabase upload error:', error);
      return NextResponse.json({ error: "Internal server error" }, { status: 500 });
     // Get public URL
    const { data: urlData } = supabase.storage
      .from(bucket)
      .getPublicUrl(filePath);

    const fileUrl = urlData.publicUrl;

    // Store file metadata in database
    const fileRecord = await prisma.uploadedFile.create({
      data: {
        fileName: file.name,
        fileUrl,
        fileSize: file.size,
        fileType: file.type,
        uploadedById: session.user.id,
        type,
        jobId: type === 'job-attachment' ? jobId : undefined,
        gigId: type === 'gig-gallery' ? gigId : undefined,
      },
    });

    return NextResponse.json({
      success: true,
      file: {
        id: fileRecord.id,
        fileName: file.name,
        fileUrl,
        fileSize: file.size,
        fileType: file.type,
        type,
      },
    });
    } catch (error) {
    console.error('Error uploading file:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   export async function DELETE(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });;
     const { searchParams } = new URL(request.url);
    const fileId = searchParams.get('fileId');

    if (!fileId) {
      return NextResponse.json({ error: 'File ID is required' }, { status: 400 });
     // Get file record
    const fileRecord = await prisma.uploadedFile.findUnique({
      where: { id: fileId },
    });

    if (!fileRecord) {
      return NextResponse.json({ error: 'File not found' }, { status: 404 });
     // Check if user owns the file
    if (fileRecord.uploadedById !== session.user.id) {
      return NextResponse.json({ error: 'Access denied' }, { status: 403 });
     // Extract file path from URL
    const url = new URL(fileRecord.fileUrl);
    const pathParts = url.pathname.split('/');
    const bucket = pathParts[pathParts.length - 2]; // bucket name
    const fileName = pathParts[pathParts.length - 1]; // file name
    
    // Determine full path based on type
    let filePath = '';
    switch (fileRecord.type) {
      case 'job-attachment':
        filePath = `jobs/${fileRecord.jobId}/${fileName}`;
        break;
      case 'gig-gallery':
        filePath = `gigs/${fileRecord.gigId}/${fileName}`;
        break;
      case 'message-file':
        filePath = `messages/${session.user.id}/${fileName}`;
        break;
     // Delete from Supabase Storage
    const { error } = await supabase.storage
      .from(bucket === 'gallery' ? 'gallery' : 'attachments')
      .remove([filePath]);

    if (error) {
      console.error('Supabase delete error:', error);
     // Delete from database
    await prisma.uploadedFile.delete({
      where: { id: fileId },
    });

    return NextResponse.json({
      success: true,
      message: 'File deleted successfully',
    });
  } catch (error) {
    console.error('Error deleting file:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }


}
}}
}}}}