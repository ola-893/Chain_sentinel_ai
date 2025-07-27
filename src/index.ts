// index.ts - Main entry point
import { validateEnvironment, createExampleEnv } from './config/validator';
import { EnhancedSeiThreatDetector } from './core/enhanced-sei-detector';
import { testSystem, showHelp } from './utils/tests';
import { ThreatAlert } from './types/index';

// Export all main classes and types for use in other modules
export {
  EnhancedSeiThreatDetector,
  SocialAlertSystem,
  HiveIntelligenceService,
  SeiBlockchainService,
  LocalThreatDetector,
  ThreatProcessor
} from './core/enhanced-sei-detector';

// Main execution function
async function main(): Promise<void> {
  console.log('🎯 Enhanced Sei Autonomous Threat Detection Agent');
  console.log('==================================================');
  console.log('📡 Real blockchain data integration with Sei Network');
  console.log('🚨 Advanced social alerting system');
  console.log('🧠 Optional Hive Intelligence integration');
  console.log('🛡️  Automated threat mitigation');
  console.log('🔍 Enhanced local threat detection patterns');
  console.log('📊 Real-time statistics and monitoring');
  console.log('');

  try {
    const config = validateEnvironment();
    const detector = new EnhancedSeiThreatDetector(config);

    // Set up event handlers
    detector.on('threat_detected', (threat: ThreatAlert) => {
      if (threat.confidence > 0.9) {
        console.log('🔥 HIGH CONFIDENCE THREAT - Additional monitoring activated');
      }
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      console.log('\n🛑 Received shutdown signal...');
      await detector.stop();
      process.exit(0);
    });

    // Start the detector
    await detector.start();

    console.log('🎯 Enhanced autonomous threat detection is now active!');
    console.log('🚨 Real-time alerts configured for Discord, Slack, and Telegram');
    console.log('📊 Statistics will be reported every 5 minutes');
    console.log('🛑 Press Ctrl+C to stop\n');

    // Keep process running
    process.stdin.resume();

  } catch (error) {
    console.error('❌ Failed to start enhanced threat detector:', error);
    console.error('\n💡 Troubleshooting tips:');
    console.error('   1. Check your .env file configuration');
    console.error('   2. Verify your private key is set');
    console.error('   3. Ensure Discord webhook URL is correct');
    console.error('   4. Check network connectivity to Sei RPC');
    process.exit(1);
  }
}

const args = process.argv.slice(2);

if (args.includes('--test')) {
  testSystem().catch(console.error);
} else if (args.includes('--example-env')) {
  createExampleEnv();
} else if (args.includes('--help')) {
  showHelp();
} else {
  main().catch(console.error);
}