// config/validator.ts
import * as dotenv from 'dotenv';
import { DetectorConfig } from '../types/index';

// Load environment variables
dotenv.config();

export function validateEnvironment(): DetectorConfig {
  const config: DetectorConfig = {
    privateKey: process.env.PRIVATE_KEY || '',
    seiApiKey: process.env.SEI_API_KEY,
    seiRpcUrl: process.env.SEI_RPC_URL || 'https://evm-rpc.sei-apis.com',
    pollingInterval: parseInt(process.env.POLLING_INTERVAL || '200'),
    threatThresholds: {
      liquidityDrain: parseFloat(process.env.LIQUIDITY_DRAIN_THRESHOLD || '75'),
      unusualVolumeSpike: parseFloat(process.env.VOLUME_SPIKE_THRESHOLD || '8'),
      gasAnomalyThreshold: parseFloat(process.env.GAS_ANOMALY_THRESHOLD || '120000000000'),
      rugPullVelocityThreshold: parseFloat(process.env.RUG_PULL_VELOCITY_THRESHOLD || '50'),
      flashLoanMinValue: parseFloat(process.env.FLASH_LOAN_MIN_VALUE || '30000000000000000000')
    },
    alerts: {
      discordWebhook: process.env.DISCORD_WEBHOOK,
      slackWebhook: process.env.SLACK_WEBHOOK,
      telegramBotToken: process.env.TELEGRAM_BOT_TOKEN,
      telegramChatId: process.env.TELEGRAM_CHAT_ID
    },
    hiveIntelligence: {
      apiKey: process.env.HIVE_API_KEY,
      endpoint: process.env.HIVE_ENDPOINT || 'https://api.hiveintelligence.xyz',
      enabled: process.env.HIVE_ENABLED !== 'false'
    },
    mitigation: {
      enabled: process.env.MITIGATION_ENABLED === 'true',
      autoFreeze: process.env.AUTO_FREEZE === 'true',
      emergencyPause: process.env.EMERGENCY_PAUSE === 'true',
      maxGas: parseInt(process.env.MAX_MITIGATION_GAS || '500000')
    }
  };

  console.log('🔧 Environment Configuration:');
  console.log(`   Private Key: ${config.privateKey ? '✅ Loaded' : '❌ Missing'}`);
  console.log(`   Sei API Key: ${config.seiApiKey ? '✅ Loaded' : '⚠️  Optional - not set'}`);
  console.log(`   RPC URL: ${config.seiRpcUrl}`);
  console.log(`   Discord Webhook: ${config.alerts.discordWebhook ? '✅ Configured' : '❌ Missing'}`);
  console.log(`   Hive Intelligence: ${config.hiveIntelligence.apiKey && config.hiveIntelligence.enabled ? '✅ Configured' : '⚠️  Disabled or missing'}`);

  if (!config.privateKey) {
    throw new Error('PRIVATE_KEY is required in .env file');
  }

  return config;
}

export function createExampleEnv(): void {
  const exampleEnv = `# Sei Threat Detector Configuration

# Required
PRIVATE_KEY=your_private_key_here

# Sei Configuration
SEI_API_KEY=your_sei_api_key_here
SEI_RPC_URL=https://evm-rpc.sei-apis.com

# Monitoring Configuration
POLLING_INTERVAL=200
LIQUIDITY_DRAIN_THRESHOLD=75
VOLUME_SPIKE_THRESHOLD=8
GAS_ANOMALY_THRESHOLD=120000000000
RUG_PULL_VELOCITY_THRESHOLD=50
FLASH_LOAN_MIN_VALUE=30000000000000000000

# Alert Configuration
DISCORD_WEBHOOK=https://discord.com/api/webhooks/your_webhook_here
SLACK_WEBHOOK=https://hooks.slack.com/services/your_webhook_here
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here

# Hive Intelligence (Optional)
HIVE_ENABLED=false
HIVE_API_KEY=your_hive_api_key_here
HIVE_ENDPOINT=https://api.hiveintelligence.xyz

# Mitigation Configuration
MITIGATION_ENABLED=false
AUTO_FREEZE=false
EMERGENCY_PAUSE=false
MAX_MITIGATION_GAS=500000
`;

  console.log('📄 Example .env configuration:');
  console.log(exampleEnv);
}