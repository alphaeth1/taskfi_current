import { Connection, PublicKey, LAMPORTS_PER_SOL } from '@solana/web3.js'
import { WalletAdapterNetwork } from '@solana/wallet-adapter-base'

export const SOLANA_NETWORK = (process.env.NEXT_PUBLIC_SOLANA_NETWORK as WalletAdapterNetwork) || WalletAdapterNetwork.Devnet

export const getConnection = () => {
  const rpcUrl = process.env.NEXT_PUBLIC_SOLANA_RPC_URL || 'https://api.devnet.solana.com'
  return new Connection(rpcUrl, 'confirmed')
}

export const formatSolAmount = (lamports: number): string => {
  return (lamports / LAMPORTS_PER_SOL).toFixed(4)
}

export const isValidSolanaAddress = (address: string): boolean => {
  try {
    new PublicKey(address)
    return true
  } catch {
    return false
  }
}

export const shortenAddress = (address: string, chars = 4): string => {
  if (!address) return ''
  return `${address.slice(0, chars)}...${address.slice(-chars)}`
}

// USDC Token addresses for different networks
export const USDC_MINT_ADDRESSES = {
  [WalletAdapterNetwork.Mainnet]: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  [WalletAdapterNetwork.Devnet]: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
  [WalletAdapterNetwork.Testnet]: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'
}

export const getUsdcMintAddress = (network: WalletAdapterNetwork = SOLANA_NETWORK): string => {
  return USDC_MINT_ADDRESSES[network]
}