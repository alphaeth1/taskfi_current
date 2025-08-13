import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

async function main() {
  console.log('Starting database seed...')

  // Create initial categories
  const categories = [
    {
      name: 'Smart Contract Development',
      description: 'Solana, Ethereum, and other blockchain smart contract development',
      icon: '⚡',
    },
    {
      name: 'DeFi Development',
      description: 'Decentralized finance protocols and applications',
      icon: '💰',
    },
    {
      name: 'NFT Development',
      description: 'Non-fungible token creation and marketplace development',
      icon: '🎨',
    },
    {
      name: 'Web3 Frontend',
      description: 'Frontend development for decentralized applications',
      icon: '🌐',
    },
    {
      name: 'Tokenomics',
      description: 'Token economics design and analysis',
      icon: '📊',
    },
    {
      name: 'Blockchain Architecture',
      description: 'System design and architecture for blockchain projects',
      icon: '🏗️',
    },
    {
      name: 'DAO Development',
      description: 'Decentralized autonomous organization development',
      icon: '🗳️',
    },
    {
      name: 'GameFi Development',
      description: 'Gaming and finance integration on blockchain',
      icon: '🎮',
    },
    {
      name: 'Web3 Security',
      description: 'Smart contract auditing and security testing',
      icon: '🛡️',
    },
    {
      name: 'Metaverse Development',
      description: 'Virtual worlds and metaverse applications',
      icon: '🌍',
    },
    {
      name: 'Crypto Trading Bots',
      description: 'Automated trading systems and algorithms',
      icon: '🤖',
    },
    {
      name: 'Solana Development',
      description: 'Solana-specific development and Rust programming',
      icon: '🔥',
    },
    {
      name: 'Web3 Marketing',
      description: 'Marketing and community building for Web3 projects',
      icon: '📢',
    },
    {
      name: 'Crypto Analysis',
      description: 'Technical and fundamental analysis of cryptocurrencies',
      icon: '📈',
    },
    {
      name: 'Blockchain Integration',
      description: 'Integration of blockchain with existing systems',
      icon: '🔗',
    },
    {
      name: 'Web3 UI/UX Design',
      description: 'User interface and experience design for Web3',
      icon: '✨',
    },
    {
      name: 'Cross-chain Development',
      description: 'Multi-blockchain and bridge development',
      icon: '🌉',
    },
    {
      name: 'Consensus Mechanisms',
      description: 'Blockchain consensus algorithm development',
      icon: '⚖️',
    },
    {
      name: 'Crypto Payment Systems',
      description: 'Payment processing and wallet integration',
      icon: '💳',
    },
    {
      name: 'Web3 Data Analytics',
      description: 'Blockchain data analysis and visualization',
      icon: '📊',
    },
  ]

  console.log('Creating categories...')
  for (const category of categories) {
    await prisma.category.upsert({
      where: { name: category.name },
      update: {},
      create: category,
    })
  }

  // Create admin user
  console.log('Creating admin user...')
  await prisma.user.upsert({
    where: { walletAddress: 'vM6Xvy4XBZyLNWK9kBLgiRf4YaEQsFu2XDiWJ4PRkqJ' },
    update: {},
    create: {
      walletAddress: 'vM6Xvy4XBZyLNWK9kBLgiRf4YaEQsFu2XDiWJ4PRkqJ',
      name: 'TaskFi Admin',
      username: 'taskfi_admin',
      bio: 'Platform administrator for TaskFi decentralized marketplace',
      role: 'ADMIN',
      isVerified: true,
      avatarUrl: '/avatars/blockchain-architect.png',
    },
  })

  // Initialize platform stats
  console.log('Initializing platform stats...')
  await prisma.platformStats.upsert({
    where: { id: 'platform_stats' },
    update: {},
    create: {
      id: 'platform_stats',
      totalUsers: 1,
      totalFreelancers: 0,
      totalHirers: 0,
      totalJobs: 0,
      totalGigs: 0,
      totalTransactions: 0,
      totalVolume: 0,
    },
  })

  console.log('Database seeded successfully!')
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })