import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!

export const supabase = createClient(supabaseUrl, supabaseAnonKey)

export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export interface Database {
  public: {
    Tables: {
      users: {
        Row: {
          id: string
          wallet_address: string
          name: string
          username: string
          bio: string | null
          avatar_url: string | null
          role: 'FREELANCER' | 'HIRER' | 'ADMIN'
          is_verified: boolean
          categories: string[]
          rating: number
          total_earned: number
          total_spent: number
          is_active: boolean
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          wallet_address: string
          name: string
          username: string
          bio?: string | null
          avatar_url?: string | null
          role: 'FREELANCER' | 'HIRER' | 'ADMIN'
          is_verified?: boolean
          categories?: string[]
          rating?: number
          total_earned?: number
          total_spent?: number
          is_active?: boolean
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          wallet_address?: string
          name?: string
          username?: string
          bio?: string | null
          avatar_url?: string | null
          role?: 'FREELANCER' | 'HIRER' | 'ADMIN'
          is_verified?: boolean
          categories?: string[]
          rating?: number
          total_earned?: number
          total_spent?: number
          is_active?: boolean
          created_at?: string
          updated_at?: string
        }
      }
    }
  }
}