import { z } from 'zod'

// Common validation schemas
export const commonSchemas = {
  // User validation
  walletAddress: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/, 'Invalid wallet address'),
  username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, hyphens, and underscores'),
  email: z.string().email('Invalid email format'),
  
  // Content validation
  title: z.string().min(5).max(200).trim(),
  description: z.string().min(10).max(5000).trim(),
  bio: z.string().max(1000).trim().optional(),
  
  // Numeric validation
  positiveNumber: z.number().positive('Must be a positive number'),
  budget: z.number().min(1).max(1000000, 'Budget must be between $1 and $1,000,000'),
  rating: z.number().min(1).max(5),
  
  // ID validation
  cuid: z.string().cuid('Invalid ID format'),
  
  // File validation
  fileName: z.string().min(1).max(255),
  fileSize: z.number().max(10 * 1024 * 1024, 'File size must be less than 10MB'),
  
  // Pagination
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
  
  // Sorting
  sortBy: z.enum(['created_at', 'updated_at', 'title', 'budget', 'rating']).optional(),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
}

// User registration schema
export const userRegistrationSchema = z.object({
  walletAddress: commonSchemas.walletAddress,
  name: z.string().min(2).max(50).trim(),
  username: commonSchemas.username,
  bio: commonSchemas.bio,
  role: z.enum(['FREELANCER', 'HIRER']),
  categories: z.array(z.string()).max(10, 'Maximum 10 categories allowed').optional(),
  avatarUrl: z.string().url().optional(),
})

// Job creation schema
export const jobCreationSchema = z.object({
  title: commonSchemas.title,
  description: commonSchemas.description,
  requirements: z.array(z.string().min(3).max(200)).min(1, 'At least one requirement is needed'),
  budget: commonSchemas.budget,
  deadline: z.string().datetime().optional(),
  categoryId: commonSchemas.cuid,
  isUrgent: z.boolean().default(false),
  tags: z.array(z.string().min(2).max(30)).max(10, 'Maximum 10 tags allowed').optional(),
  attachments: z.array(z.string().url()).max(5, 'Maximum 5 attachments allowed').optional(),
})

// Job application schema
export const jobApplicationSchema = z.object({
  jobId: commonSchemas.cuid,
  coverLetter: z.string().min(50).max(2000).trim(),
  proposedBudget: commonSchemas.budget,
  estimatedDays: z.number().int().min(1).max(365),
  attachments: z.array(z.string().url()).max(3, 'Maximum 3 attachments allowed').optional(),
})

// Gig creation schema
export const gigCreationSchema = z.object({
  title: commonSchemas.title,
  description: commonSchemas.description,
  deliverables: z.array(z.string().min(5).max(200)).min(1, 'At least one deliverable is needed'),
  packages: z.object({
    basic: z.object({
      name: z.string().min(5).max(50),
      description: z.string().min(10).max(500),
      price: commonSchemas.budget,
      deliveryDays: z.number().int().min(1).max(90),
      features: z.array(z.string().min(3).max(100)).min(1),
    }),
    standard: z.object({
      name: z.string().min(5).max(50),
      description: z.string().min(10).max(500),
      price: commonSchemas.budget,
      deliveryDays: z.number().int().min(1).max(90),
      features: z.array(z.string().min(3).max(100)).min(1),
    }).optional(),
    premium: z.object({
      name: z.string().min(5).max(50),
      description: z.string().min(10).max(500),
      price: commonSchemas.budget,
      deliveryDays: z.number().int().min(1).max(90),
      features: z.array(z.string().min(3).max(100)).min(1),
    }).optional(),
  }),
  categoryId: commonSchemas.cuid,
  tags: z.array(z.string().min(2).max(30)).max(10, 'Maximum 10 tags allowed').optional(),
  gallery: z.array(z.string().url()).max(10, 'Maximum 10 gallery images allowed').optional(),
})

// Message schema
export const messageSchema = z.object({
  jobId: commonSchemas.cuid,
  content: z.string().min(1).max(2000).trim(),
  type: z.enum(['TEXT', 'FILE', 'IMAGE']).default('TEXT'),
  fileUrl: z.string().url().optional(),
})

// Review schema
export const reviewSchema = z.object({
  targetId: commonSchemas.cuid,
  rating: commonSchemas.rating,
  comment: z.string().min(10).max(1000).trim().optional(),
  jobId: commonSchemas.cuid.optional(),
  gigId: commonSchemas.cuid.optional(),
})

// Payment schema
export const paymentSchema = z.object({
  amount: commonSchemas.budget,
  currency: z.enum(['USDC', 'SOL']).default('USDC'),
  jobId: commonSchemas.cuid.optional(),
  gigId: commonSchemas.cuid.optional(),
})

// Search and filter schemas
export const jobSearchSchema = z.object({
  query: z.string().max(100).trim().optional(),
  categoryId: commonSchemas.cuid.optional(),
  minBudget: z.number().positive().optional(),
  maxBudget: z.number().positive().optional(),
  isUrgent: z.boolean().optional(),
  tags: z.array(z.string()).optional(),
  page: commonSchemas.page,
  limit: commonSchemas.limit,
  sortBy: commonSchemas.sortBy,
  sortOrder: commonSchemas.sortOrder,
})

export const gigSearchSchema = z.object({
  query: z.string().max(100).trim().optional(),
  categoryId: commonSchemas.cuid.optional(),
  minPrice: z.number().positive().optional(),
  maxPrice: z.number().positive().optional(),
  deliveryTime: z.number().int().min(1).max(90).optional(),
  rating: z.number().min(1).max(5).optional(),
  tags: z.array(z.string()).optional(),
  page: commonSchemas.page,
  limit: commonSchemas.limit,
  sortBy: z.enum(['created_at', 'rating', 'order_count', 'price']).optional(),
  sortOrder: commonSchemas.sortOrder,
})

// Admin schemas
export const adminUserUpdateSchema = z.object({
  userId: commonSchemas.cuid,
  role: z.enum(['FREELANCER', 'HIRER', 'ADMIN']).optional(),
  isActive: z.boolean().optional(),
  isVerified: z.boolean().optional(),
})

// Utility functions for validation
export function sanitizeHtml(input: string): string {
  // Remove script tags and other dangerous HTML
  return input
    .replace(/<script[^>]*>.*?<\/script>/gi, '')
    .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
    .replace(/<object[^>]*>.*?<\/object>/gi, '')
    .replace(/<embed[^>]*>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
}

export function sanitizeInput(input: string): string {
  // Basic sanitization for text inputs
  return input
    .trim()
    .replace(/[<>\"'&]/g, (match) => {
      const entityMap: { [key: string]: string } = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;',
      }
      return entityMap[match] || match
    })
}

export function validateFileType(fileName: string, allowedTypes: string[]): boolean {
  const extension = fileName.split('.').pop()?.toLowerCase()
  return extension ? allowedTypes.includes(extension) : false
}

export function validateImageType(fileName: string): boolean {
  return validateFileType(fileName, ['jpg', 'jpeg', 'png', 'gif', 'webp'])
}

export function validateDocumentType(fileName: string): boolean {
  return validateFileType(fileName, ['pdf', 'doc', 'docx', 'txt', 'md'])
}

// Error handling for validation
export class ValidationError extends Error {
  constructor(
    message: string,
    public field?: string,
    public code?: string
  ) {
    super(message)
    this.name = 'ValidationError'
  }
}

export function handleValidationError(error: z.ZodError): ValidationError[] {
  return error.errors.map(err => new ValidationError(
    err.message,
    err.path.join('.'),
    err.code
  ))
}

// Middleware for API route validation
export function validateRequestBody<T>(schema: z.ZodSchema<T>) {
  return (requestBody: any): T => {
    try {
      return schema.parse(requestBody)
    } catch (error) {
      if (error instanceof z.ZodError) {
        const validationErrors = handleValidationError(error)
        throw new ValidationError(
          `Validation failed: ${validationErrors.map(e => e.message).join(', ')}`
        )
      }
      throw error
    }
  }
}

// Rate limiting validation schemas
export const rateLimitSchemas = {
  auth: z.object({
    action: z.enum(['login', 'register', 'forgot-password']),
    identifier: z.string().min(1), // email or wallet address
  }),
  
  api: z.object({
    endpoint: z.string(),
    method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']),
  }),
}