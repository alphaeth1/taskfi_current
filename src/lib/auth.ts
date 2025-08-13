import { NextAuthOptions } from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'
import { getCsrfToken } from 'next-auth/react'
import { SigninMessage } from './auth/SigninMessage'
import { prisma } from './prisma'
import { PublicKey } from '@solana/web3.js'
import nacl from 'tweetnacl'
import bs58 from 'bs58'

export interface AuthUser {
  id: string
  walletAddress: string
  name: string
  username: string
  role: 'FREELANCER' | 'HIRER' | 'ADMIN'
  avatarUrl?: string
  isVerified: boolean
}

declare module 'next-auth' {
  interface Session {
    user: AuthUser
  }
  interface User {
    id: string
    walletAddress: string
    name: string
    username: string
    role: 'FREELANCER' | 'HIRER' | 'ADMIN'
    avatarUrl?: string
    isVerified: boolean
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    user: AuthUser
  }
}

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: 'Solana',
      credentials: {
        message: {
          label: 'Message',
          type: 'text',
        },
        signature: {
          label: 'Signature',
          type: 'text',
        },
      },
      async authorize(credentials, req) {
        try {
          if (!credentials?.message || !credentials?.signature) {
            throw new Error('Missing credentials')
          }

          const signinMessage = new SigninMessage(JSON.parse(credentials.message))
          const validationResult = await signinMessage.validate(credentials.signature)

          if (!validationResult) {
            throw new Error('Invalid signature')
          }

          // Check if user exists in database
          const existingUser = await prisma.user.findUnique({
            where: { walletAddress: signinMessage.publicKey },
          })

          if (!existingUser) {
            // Return wallet address for new user flow
            return {
              id: 'new-user',
              walletAddress: signinMessage.publicKey,
              name: '',
              username: '',
              role: 'FREELANCER' as const,
              isVerified: false,
            }
          }

          // Return existing user
          return {
            id: existingUser.id,
            walletAddress: existingUser.walletAddress,
            name: existingUser.name,
            username: existingUser.username,
            role: existingUser.role as 'FREELANCER' | 'HIRER' | 'ADMIN',
            avatarUrl: existingUser.avatarUrl || undefined,
            isVerified: existingUser.isVerified,
          }
        } catch (error) {
          console.error('Auth error:', error)
          return null
        }
      },
    }),
  ],
  session: { strategy: 'jwt' },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.user = user as AuthUser
      }
      return token
    },
    async session({ session, token }) {
      session.user = token.user
      return session
    },
  },
  pages: {
    signIn: '/auth/signin',
    newUser: '/onboarding',
  },
  secret: process.env.NEXTAUTH_SECRET,
}

// Wallet verification utilities
export class WalletVerificationService {
  // Verify wallet ownership by signing a message
  static async verifyWalletOwnership(
    publicKey: string,
    signature: string,
    message: string
  ): Promise<boolean> {
    try {
      const publicKeyBytes = new PublicKey(publicKey).toBytes()
      const messageBytes = new TextEncoder().encode(message)
      const signatureBytes = bs58.decode(signature)

      return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes)
    } catch (error) {
      console.error('Wallet verification error:', error)
      return false
    }
  }

  // Generate verification message
  static generateVerificationMessage(publicKey: string, nonce: string): string {
    return `TaskFi Wallet Verification\n\nPublic Key: ${publicKey}\nNonce: ${nonce}\nTimestamp: ${Date.now()}`
  }

  // Verify signature for authentication
  static async verifySignature(
    publicKey: string,
    signature: string,
    message: string
  ): Promise<boolean> {
    try {
      const publicKeyObj = new PublicKey(publicKey)
      const messageBytes = new TextEncoder().encode(message)
      const signatureBytes = bs58.decode(signature)

      return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyObj.toBytes())
    } catch (error) {
      console.error('Signature verification error:', error)
      return false
    }
  }

  // Create user after successful wallet verification
  static async createUser(userData: {
    walletAddress: string
    name: string
    username: string
    bio?: string
    role: 'FREELANCER' | 'HIRER'
    categories?: string[]
    avatarUrl?: string
  }): Promise<AuthUser> {
    try {
      // Check if username is already taken
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [
            { username: userData.username },
            { walletAddress: userData.walletAddress },
          ],
        },
      })

      if (existingUser) {
        throw new Error('Username or wallet address already exists')
      }

      // Create new user
      const user = await prisma.user.create({
        data: {
          walletAddress: userData.walletAddress,
          name: userData.name,
          username: userData.username,
          bio: userData.bio,
          role: userData.role,
          categories: userData.categories || [],
          avatarUrl: userData.avatarUrl,
          isVerified: true, // Auto-verify since wallet is verified
        },
      })

      return {
        id: user.id,
        walletAddress: user.walletAddress,
        name: user.name,
        username: user.username,
        role: user.role as 'FREELANCER' | 'HIRER' | 'ADMIN',
        avatarUrl: user.avatarUrl || undefined,
        isVerified: user.isVerified,
      }
    } catch (error) {
      console.error('User creation error:', error)
      throw error
    }
  }

  // Update user profile
  static async updateUser(
    userId: string,
    updateData: {
      name?: string
      username?: string
      bio?: string
      avatarUrl?: string
      categories?: string[]
    }
  ): Promise<AuthUser> {
    try {
      // Check if new username is taken (if provided)
      if (updateData.username) {
        const existingUser = await prisma.user.findFirst({
          where: {
            username: updateData.username,
            NOT: { id: userId },
          },
        })

        if (existingUser) {
          throw new Error('Username already taken')
        }
      }

      const user = await prisma.user.update({
        where: { id: userId },
        data: updateData,
      })

      return {
        id: user.id,
        walletAddress: user.walletAddress,
        name: user.name,
        username: user.username,
        role: user.role as 'FREELANCER' | 'HIRER' | 'ADMIN',
        avatarUrl: user.avatarUrl || undefined,
        isVerified: user.isVerified,
      }
    } catch (error) {
      console.error('User update error:', error)
      throw error
    }
  }

  // Check username availability
  static async isUsernameAvailable(username: string): Promise<boolean> {
    try {
      const existingUser = await prisma.user.findUnique({
        where: { username },
      })
      return !existingUser
    } catch (error) {
      console.error('Username check error:', error)
      return false
    }
  }

  // Get user by wallet address
  static async getUserByWallet(walletAddress: string): Promise<AuthUser | null> {
    try {
      const user = await prisma.user.findUnique({
        where: { walletAddress },
      })

      if (!user) return null

      return {
        id: user.id,
        walletAddress: user.walletAddress,
        name: user.name,
        username: user.username,
        role: user.role as 'FREELANCER' | 'HIRER' | 'ADMIN',
        avatarUrl: user.avatarUrl || undefined,
        isVerified: user.isVerified,
      }
    } catch (error) {
      console.error('Get user error:', error)
      return null
    }
  }

  // Verify admin role
  static async isAdmin(userId: string): Promise<boolean> {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { role: true },
      })
      return user?.role === 'ADMIN'
    } catch (error) {
      console.error('Admin check error:', error)
      return false
    }
  }
}

// Role-based permission utilities
export class PermissionService {
  static canAccessAdminPanel(role: string): boolean {
    return role === 'ADMIN'
  }

  static canManageJobs(role: string): boolean {
    return role === 'HIRER' || role === 'ADMIN'
  }

  static canManageGigs(role: string): boolean {
    return role === 'FREELANCER' || role === 'ADMIN'
  }

  static canApplyToJobs(role: string): boolean {
    return role === 'FREELANCER'
  }

  static canPostJobs(role: string): boolean {
    return role === 'HIRER'
  }

  static canManageCategories(role: string): boolean {
    return role === 'ADMIN'
  }

  static canModerateDisputes(role: string): boolean {
    return role === 'ADMIN'
  }

  static canAccessUserManagement(role: string): boolean {
    return role === 'ADMIN'
  }

  static canManagePayments(role: string): boolean {
    return role === 'ADMIN'
  }
}

// Middleware for API route protection
export function requireAuth(role?: 'FREELANCER' | 'HIRER' | 'ADMIN') {
  return async (req: any, res: any, next: any) => {
    try {
      // In a real implementation, you'd extract the user from the session/token
      const user = req.user as AuthUser | undefined

      if (!user) {
        return res.status(401).json({ error: 'Authentication required' })
      }

      if (role && user.role !== role && user.role !== 'ADMIN') {
        return res.status(403).json({ error: 'Insufficient permissions' })
      }

      next()
    } catch (error) {
      return res.status(500).json({ error: 'Authentication error' })
    }
  }
}

// Generate secure nonce for wallet verification
export function generateNonce(): string {
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15)
}