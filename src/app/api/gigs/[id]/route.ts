import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, PermissionService } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'

const packageSchema = z.object({
  name: z.string().min(1).max(50),
  description: z.string().min(10).max(500),
  price: z.number().min(5).max(100000),
  deliveryDays: z.number().min(1).max(90),
  revisions: z.number().min(0).max(10),
  features: z.array(z.string()).min(1).max(20),
})

const updateGigSchema = z.object({
  title: z.string().min(10).max(100).optional(),
  description: z.string().min(100).max(2000).optional(),
  deliverables: z.array(z.string()).min(1).max(10).optional(),
  packages: z.array(packageSchema).min(1).max(3).optional(),
  gallery: z.array(z.string()).max(10).optional(),
  tags: z.array(z.string()).max(10).optional(),
  categoryId: z.string().optional(),
  status: z.enum(['ACTIVE', 'PAUSED', 'INACTIVE']).optional(),
})


// GET /api/gigs/[id] - Get gig details
export async function GET(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    
    const gig = await prisma.gig.findUnique({
      where: { id: params.id },
      include: {
        freelancer: {
          select: {
            id: true,
            name: true,
            username: true,
            avatarUrl: true,
            rating: true,
            isVerified: true,
            totalEarned: true,
            completedJobs: true,
            createdAt: true,
            categories: true,
          },
        },
        category: {
          select: {
            id: true,
            name: true,
            icon: true,
          },
        },
        reviews: {
          where: { isPublic: true },
          include: {
            author: {
              select: {
                id: true,
                name: true,
                username: true,
                avatarUrl: true,
              },
            },
          },
          orderBy: { createdAt: 'desc' },
          take: 20,
        },
        payments: session ? {
          where: {
            OR: [
              { userId: session.user.id },
              { gig: { freelancerId: session.user.id } }
            ]
          },
          select: {
            id: true,
            amount: true,
            status: true,
            createdAt: true,
            packageDetails: true,
          },
          orderBy: { createdAt: 'desc' },
        } : false,
        _count: {
          select: {
            reviews: true,
            payments: true,
          },
        },
      },
    })

    if (!gig) {
      return NextResponse.json({ error: 'Gig not found' }, { status: 404 });
     // Increment view count (but don't count owner views)
    if (!session || session.user.id !== gig.freelancerId) {
      await prisma.gig.update({
        where: { id: params.id },
        data: { viewCount: { increment: 1 } },
      })
     // Calculate derived fields
    const packages = gig.packages as any[]
    const minPrice = packages.length > 0 ? Math.min(...packages.map(p => p.price)) : 0
    const maxPrice = packages.length > 0 ? Math.max(...packages.map(p => p.price)) : 0
    const minDelivery = packages.length > 0 ? Math.min(...packages.map(p => p.deliveryDays)) : 0

    // Calculate review statistics
    const reviews = gig.reviews
    const avgRating = reviews.length > 0 
      ? reviews.reduce((sum, review) => sum + review.rating, 0) / reviews.length 
      : gig.rating

    // Get related gigs from the same freelancer
    const relatedGigs = await prisma.gig.findMany({
      where: {
        freelancerId: gig.freelancerId,
        id: { not: params.id },
        status: 'ACTIVE',
      },
      select: {
        id: true,
        title: true,
        packages: true,
        gallery: true,
        rating: true,
        orderCount: true,
      },
      take: 4,
      orderBy: { orderCount: 'desc' },
    })

    // Process related gigs
    const processedRelatedGigs = relatedGigs.map(relatedGig => {
      const relatedPackages = relatedGig.packages as any[]
      return {
        ...relatedGig,
        minPrice: relatedPackages.length > 0 ? Math.min(...relatedPackages.map(p => p.price)) : 0,
       });

    return NextResponse.json({ 
      gig: {
        ...gig,
        minPrice,
        maxPrice,
        minDelivery,
        avgRating,
        reviewCount: gig._count.reviews,
        totalOrders: gig._count.payments,
        relatedGigs: processedRelatedGigs,
       });
  } catch (error) {
    console.error('Get gig error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // PUT /api/gigs/[id] - Update gig
export async function PUT(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     const body = await request.json()
    const updateData = updateGigSchema.parse(body)

    // Check if user owns the gig or is admin
    const gig = await prisma.gig.findUnique({
      where: { id: params.id },
      select: { freelancerId: true, status: true },
    })

    if (!gig) {
      return NextResponse.json({ error: 'Gig not found' }, { status: 404 })
     const canUpdate = gig.freelancerId === session.user.id || 
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
        return NextResponse.json({ error: "Internal server}
 error" }, { status: 400 });
      }
    }

    // Validate packages if provided
    if (updateData.packages) {
      const packages = updateData.packages
      
      // Ensure packages are in ascending price order
      for (let i = 1; i < packages.length; i++) {
        if (packages[i].price <= packages[i-1].price) {
          return NextResponse.json({ error: "Internal server}
 error" }, { status: 400 });
         // Prepare update data
    const dataToUpdate: any = { ...updateData  // Handle status changes
    if (updateData.status) {
      // Can't set to ACTIVE if freelancer has 10+ active gigs
      if (updateData.status === 'ACTIVE' && gig.status !== 'ACTIVE') {
        const activeGigsCount = await prisma.gig.count({
          where: {
            freelancerId: session.user.id,
            status: 'ACTIVE',
            id: { not:}
 params.id }
          }
        })

        if (activeGigsCount >= 10) {
          return NextResponse.json({ error: "Internal server}
 error" }, { status: 400 });
        }
      }
     const updatedGig = await prisma.gig.update({
      where: { id: params.id },
      data: dataToUpdate,
      include: {
        freelancer: {
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
            reviews: true,
            payments: true,
          },
        },
      },
    })

    // Calculate derived fields
    const packages = updatedGig.packages as any[]
    const minPrice = packages.length > 0 ? Math.min(...packages.map(p => p.price)) : 0
    const maxPrice = packages.length > 0 ? Math.max(...packages.map(p => p.price)) : 0
    const minDelivery = packages.length > 0 ? Math.min(...packages.map(p => p.deliveryDays)) : 0

    return NextResponse.json({ 
      gig: {
        ...updatedGig,
        minPrice,
        maxPrice,
        minDelivery,
        reviewCount: updatedGig._count.reviews,
        totalOrders: updatedGig._count.payments,
       });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: "Invalid input" }, { status: 400 });
     console.error('Update gig error:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   // DELETE /api/gigs/[id] - Delete gig
export async function DELETE(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     // Check if user owns the gig or is admin
    const gig = await prisma.gig.findUnique({
      where: { id: params.id },
      select: { 
        freelancerId: true, 
        status: true,
        _count: {
          select: {
            payments: true,
            applications: true,
          },
        },
      },
    })

    if (!gig) {
      return NextResponse.json({ error: 'Gig not found' }, { status: 404 })
     const canDelete = gig.freelancerId === session.user.id || 
                     PermissionService.canAccessUserManagement(session.user.role)

    if (!canDelete) {
      return NextResponse.json({ error: 'Forbidden'  }, { status: 403 });
     // Don't allow deletion if gig has payments
    if (gig._count.payments > 0) {
      return NextResponse.json({ error: "Cannot delete gig with existing payments" }, { status: 400 });
     // Don't allow deletion if gig has pending applications (for gig applications)
    if (gig._count.applications > 0) {
      return NextResponse.json({ error: "Cannot delete gig with pending applications" }, { status: 400 });
     // Can only delete INACTIVE gigs or set to INACTIVE first
    if (gig.status !== 'INACTIVE') {
      return NextResponse.json({ error: "Can only delete inactive gigs" }, { status: 400 });
     await prisma.gig.delete({
      where: { id: params.id },
    })

    return NextResponse.json({ message: 'Gig deleted successfully' });
  } catch (error) {
    console.error('Delete gig error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
}
}}}
}
}