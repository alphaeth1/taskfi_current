"use client"

import { SessionProvider } from "next-auth/react"
import WalletContextProvider from "./WalletProvider"

export default function ClientProviders({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <SessionProvider>
      <WalletContextProvider>
        {children}
      </WalletContextProvider>
    </SessionProvider>
  )
}