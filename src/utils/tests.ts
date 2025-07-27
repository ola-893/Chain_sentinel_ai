// utils/testing.ts
import { validateEnvironment } from '../config/validator.js';
import { EnhancedSeiThreatDetector } from '../core/enhanced-sei-detector.js';

export async function testSystem(): Promise<void> {
  console.log('🧪 Testing Enhanced Sei Threat Detection System');
  console.log('================================================');

  try {
    const config = validateEnvironment();
    const detector = new EnhancedSeiThreatDetector(config);

    // Test alerts
    await detector.testAlerts();

    // Test configuration
    console.log('\n🔧 Configuration Test:');
    console.log(`   Polling interval: ${config.pollingInterval}ms`);
    console.log(`   Gas anomaly threshold: ${config.threatThresholds.gasAnomalyThreshold}`);
    console.log(`   Mitigation enabled: ${config.mitigation.enabled}`);
    console.log(`   Hive Intelligence enabled: ${config.hiveIntelligence.enabled}`);

    console.log('\n✅ System test completed successfully');
  } catch (error) {
    console.error('❌ System test failed:', error);
  }
}

export function showHelp(): void {
  console.log('🎯 Sei Threat Detector Usage:');
  console.log('   npm run dev              - Start the threat detector');
  console.log('   npm run dev -- --test    - Run system tests');
  console.log('   npm run dev -- --example-env - Show example .env file');
  console.log('   npm run dev -- --help    - Show this help message');
}