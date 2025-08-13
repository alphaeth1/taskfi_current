import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/admin-middleware';
import { prisma } from '@/lib/prisma';
import { z } from 'zod';

const updateCategorySchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().optional(),
  icon: z.string().optional(),
});

// GET /api/categories/[id] - Get category by ID with stats
export async function GET(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  
  try {
    const category = await prisma.category.findUnique({
      where: { id: params.id },
      include: {
        _count: {
          select: {
            jobs: true,
            gigs: true,
          },
        },
        jobs: {
          take: 10,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            title: true,
            budget: true,
            status: true,
            createdAt: true,
            user: {
              select: { name: true },
            },
          },
        },
        gigs: {
          take: 10,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            title: true,
            price: true,
            status: true,
            createdAt: true,
            user: {
              select: { name: true },
            },
          },
        },
      },
    });

    if (!category) {
      return NextResponse.json({ error: 'Category not found' }, { status: 404 });
    }

    return NextResponse.json({ category });
  } catch (error) {
    console.error('Get category error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

// PUT /api/categories/[id] - Update category (admin only)
export async function PUT(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  
  try {
    const adminCheck = await requireAdmin();
    if (adminCheck) return adminCheck;

    const body = await request.json();
    const updateData = updateCategorySchema.parse(body);

    // Check if category exists
    const existingCategory = await prisma.category.findUnique({
      where: { id: params.id },
    });

    if (!existingCategory) {
      return NextResponse.json({ error: 'Category not found' }, { status: 404 });
    }

    // Check name uniqueness if updating name
    if (updateData.name && updateData.name !== existingCategory.name) {
      const nameExists = await prisma.category.findFirst({
        where: { 
          name: { equals: updateData.name, mode: 'insensitive' },
          id: { not: params.id },
        },
      });

      if (nameExists) {
        return NextResponse.json({ error: 'Category name already exists' }, { status: 409 });
      }
    }

    const updatedCategory = await prisma.category.update({
      where: { id: params.id },
      data: updateData,
      include: {
        _count: {
          select: {
            jobs: true,
            gigs: true,
          },
        },
      },
    });

    return NextResponse.json({ category: updatedCategory });
  } catch (error) {
    console.error('Update category error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

// DELETE /api/categories/[id] - Delete category (admin only)
export async function DELETE(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  
  try {
    const adminCheck = await requireAdmin();
    if (adminCheck) return adminCheck;

    // Check if category exists
    const existingCategory = await prisma.category.findUnique({
      where: { id: params.id },
      include: {
        _count: {
          select: {
            jobs: true,
            gigs: true,
          },
        },
      },
    });

    if (!existingCategory) {
      return NextResponse.json({ error: 'Category not found' }, { status: 404 });
    }

    // Check if category is in use
    if (existingCategory._count.jobs > 0 || existingCategory._count.gigs > 0) {
      return NextResponse.json(
        { error: 'Cannot delete category that is in use by jobs or gigs' },
        { status: 409 }
      );
    }

    await prisma.category.delete({
      where: { id: params.id },
    });

    return NextResponse.json({ message: 'Category deleted successfully' });
  } catch (error) {
    console.error('Delete category error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}