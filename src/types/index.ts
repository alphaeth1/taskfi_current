export interface User {
  id: string
  walletAddress: string
  name: string
  username: string
  bio?: string
  avatarUrl?: string
  role: 'FREELANCER' | 'HIRER' | 'ADMIN'
  isVerified: boolean
  categories: string[]
  rating: number
  totalEarned: number
  totalSpent: number
  isActive: boolean
  createdAt: Date
  updatedAt: Date
}

export interface Job {
  id: string
  title: string
  description: string
  requirements: string[]
  budget: number
  deadline?: Date
  status: 'OPEN' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED' | 'DISPUTED'
  isUrgent: boolean
  attachments: string[]
  tags: string[]
  viewCount: number
  applicantCount: number
  hirerId: string
  hirer?: User
  categoryId: string
  category?: Category
  createdAt: Date
  updatedAt: Date
}

export interface Gig {
  id: string
  title: string
  description: string
  deliverables: string[]
  packages: GigPackage[]
  gallery: string[]
  tags: string[]
  status: 'ACTIVE' | 'PAUSED' | 'INACTIVE'
  viewCount: number
  orderCount: number
  rating: number
  freelancerId: string
  freelancer?: User
  categoryId: string
  category?: Category
  createdAt: Date
  updatedAt: Date
}

export interface GigPackage {
  name: string
  description: string
  price: number
  deliveryTime: number
  revisions: number
  features: string[]
}

export interface Category {
  id: string
  name: string
  description?: string
  icon?: string
  isActive: boolean
  createdAt: Date
  updatedAt: Date
}

export interface JobApplication {
  id: string
  coverLetter: string
  proposedBudget: number
  estimatedDays: number
  attachments: string[]
  isAccepted?: boolean
  freelancerId: string
  freelancer?: User
  jobId?: string
  job?: Job
  gigId?: string
  gig?: Gig
  createdAt: Date
  updatedAt: Date
}

export interface Message {
  id: string
  content: string
  type: 'TEXT' | 'FILE' | 'IMAGE' | 'SYSTEM'
  fileUrl?: string
  isRead: boolean
  senderId: string
  sender?: User
  receiverId: string
  receiver?: User
  jobId: string
  job?: Job
  createdAt: Date
  updatedAt: Date
}

export interface Payment {
  id: string
  amount: number
  currency: string
  status: 'PENDING' | 'ESCROW' | 'RELEASED' | 'REFUNDED' | 'DISPUTED'
  escrowAddress?: string
  transactionHash?: string
  releaseDate?: Date
  disputeReason?: string
  payerId: string
  payer?: User
  jobId?: string
  job?: Job
  gigId?: string
  gig?: Gig
  createdAt: Date
  updatedAt: Date
}

export interface Review {
  id: string
  rating: number
  comment?: string
  isPublic: boolean
  authorId: string
  author?: User
  targetId: string
  target?: User
  jobId?: string
  job?: Job
  gigId?: string
  gig?: Gig
  createdAt: Date
  updatedAt: Date
}