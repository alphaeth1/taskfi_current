import { PublicKey } from '@solana/web3.js'
import nacl from 'tweetnacl'
import bs58 from 'bs58'

export interface SigninMessageData {
  domain: string
  publicKey: string
  nonce: string
  statement?: string
}

export class SigninMessage {
  domain: string
  publicKey: string
  nonce: string
  statement: string

  constructor(data: SigninMessageData) {
    this.domain = data.domain
    this.publicKey = data.publicKey
    this.nonce = data.nonce
    this.statement = data.statement || 'Sign this message to authenticate with TaskFi'
  }

  prepare(): string {
    return `${this.statement}\n\nDomain: ${this.domain}\nPublic Key: ${this.publicKey}\nNonce: ${this.nonce}`
  }

  async validate(signature: string): Promise<boolean> {
    try {
      const message = this.prepare()
      const messageBytes = new TextEncoder().encode(message)
      const publicKeyBytes = new PublicKey(this.publicKey).toBytes()
      const signatureBytes = bs58.decode(signature)

      return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes)
    } catch (error) {
      console.error('Signature validation error:', error)
      return false
    }
  }

  static generateNonce(): string {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15)
  }
}