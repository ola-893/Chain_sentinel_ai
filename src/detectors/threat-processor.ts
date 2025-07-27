// detectors/threat-processor.ts
import { DetectorConfig, RealTransaction, ThreatAlert, HiveAnalysis } from '../types/index';
import { LocalThreatDetector } from './local-threat-detector';
import { HiveIntelligenceService } from '../services/hive-intelligence';
import { SocialAlertSystem } from '../services/alerts';

export class ThreatProcessor {
  private config: DetectorConfig;
  private localDetector: LocalThreatDetector;
  private hiveIntelligence: HiveIntelligenceService;
  private socialAlerts: SocialAlertSystem;

  constructor(
    config: DetectorConfig,
    localDetector: LocalThreatDetector,
    hiveIntelligence: HiveIntelligenceService,
    socialAlerts: SocialAlertSystem
  ) {
    this.config = config;
    this.localDetector = localDetector;
    this.hiveIntelligence = hiveIntelligence;
    this.socialAlerts = socialAlerts;
  }

  async analyzeThreatPatterns(transaction: RealTransaction): Promise<ThreatAlert[]> {
    const threats: ThreatAlert[] = [];

    try {
      // Local threat detection (always runs)
      const localThreats = await this.localDetector.detectThreats(transaction);
      threats.push(...localThreats);

      // Hive Intelligence analysis (if enabled and available)
      const hiveAnalysis = await this.hiveIntelligence.analyzeTransaction(transaction);
      if (hiveAnalysis && hiveAnalysis.threats) {
        const hiveThreats = this.processHiveThreats(transaction, hiveAnalysis);
        threats.push(...hiveThreats);
      }

      return threats;

    } catch (error) {
      console.error('❌ Error in threat analysis:', error);
      return threats;
    }
  }

  private processHiveThreats(tx: RealTransaction, hiveAnalysis: HiveAnalysis): ThreatAlert[] {
    const threats: ThreatAlert[] = [];

    // Process rug pull threats
    if (hiveAnalysis.rugPull && hiveAnalysis.rugPull.risk > 0.5) {
      threats.push({
        id: `hive_rug_pull_${tx.hash}_${Date.now()}`,
        type: 'rug_pull',
        severity: hiveAnalysis.rugPull.risk > 0.8 ? 'critical' : 'high',
        contractAddress: tx.to || '',
        transactionHash: tx.hash,
        timestamp: tx.timestamp,
        blockNumber: parseInt(tx.blockNumber, 16),
        details: {
          hiveAnalysis: hiveAnalysis.rugPull,
          indicators: hiveAnalysis.rugPull.indicators || [],
          dataSources: hiveAnalysis.dataSources || [],
          source: 'hive_intelligence'
        },
        confidence: hiveAnalysis.rugPull.risk,
        mitigated: false
      });
    }

    // Process flash loan threats
    if (hiveAnalysis.flashLoan && hiveAnalysis.flashLoan.risk > 0.6) {
      threats.push({
        id: `hive_flash_loan_${tx.hash}_${Date.now()}`,
        type: 'flash_loan_attack',
        severity: hiveAnalysis.flashLoan.risk > 0.8 ? 'critical' : 'high',
        contractAddress: tx.to || '',
        transactionHash: tx.hash,
        timestamp: tx.timestamp,
        blockNumber: parseInt(tx.blockNumber, 16),
        details: {
          hiveAnalysis: hiveAnalysis.flashLoan,
          indicators: hiveAnalysis.flashLoan.indicators || [],
          dataSources: hiveAnalysis.dataSources || [],
          source: 'hive_intelligence'
        },
        confidence: hiveAnalysis.flashLoan.risk,
        mitigated: false
      });
    }

    // Process MEV threats
    if (hiveAnalysis.mev && hiveAnalysis.mev.risk > 0.6) {
      threats.push({
        id: `hive_mev_${tx.hash}_${Date.now()}`,
        type: 'mev_attack',
        severity: hiveAnalysis.mev.risk > 0.8 ? 'high' : 'medium',
        contractAddress: tx.to || '',
        transactionHash: tx.hash,
        timestamp: tx.timestamp,
        blockNumber: parseInt(tx.blockNumber, 16),
        details: {
          hiveAnalysis: hiveAnalysis.mev,
          indicators: hiveAnalysis.mev.indicators || [],
          dataSources: hiveAnalysis.dataSources || [],
          source: 'hive_intelligence'
        },
        confidence: hiveAnalysis.mev.risk,
        mitigated: false
      });
    }

    // Process general high-risk transactions
    if (hiveAnalysis.overallRisk > 0.7 && threats.length === 0) {
      threats.push({
        id: `hive_suspicious_${tx.hash}_${Date.now()}`,
        type: 'suspicious_pattern',
        severity: hiveAnalysis.overallRisk > 0.8 ? 'high' : 'medium',
        contractAddress: tx.to || '',
        transactionHash: tx.hash,
        timestamp: tx.timestamp,
        blockNumber: parseInt(tx.blockNumber, 16),
        details: {
          overallRisk: hiveAnalysis.overallRisk,
          rawResponse: hiveAnalysis.rawResponse,
          dataSources: hiveAnalysis.dataSources || [],
          source: 'hive_intelligence'
        },
        confidence: hiveAnalysis.confidence || 0.6,
        mitigated: false
      });
    }

    return threats;
  }

  async handleThreat(threat: ThreatAlert): Promise<void> {
    // Log threat
    console.log(`\n🚨 THREAT DETECTED [${new Date(threat.timestamp).toISOString()}]`);
    console.log(`   ⚠️ Type: ${threat.type.toUpperCase().replace('_', ' ')}`);
    console.log(`   📊 Severity: ${threat.severity.toUpperCase()}`);
    console.log(`   🎯 Confidence: ${(threat.confidence * 100).toFixed(1)}%`);
    console.log(`   📝 Contract: ${threat.contractAddress.substr(0, 10)}...`);
    console.log(`   🔗 Transaction: ${threat.transactionHash.substr(0, 10)}...`);

    // Send social alerts for medium+ severity threats
    if (threat.severity === 'medium' || threat.severity === 'high' || threat.severity === 'critical') {
      await this.socialAlerts.sendAlert(threat);
    }

    // Auto-mitigation for critical threats
    if (this.config.mitigation.enabled && threat.severity === 'critical' && threat.confidence > 0.8) {
      await this.executeMitigation(threat);
    }
  }

  private async executeMitigation(threat: ThreatAlert): Promise<void> {
    console.log(`\n🛡️  AUTO-MITIGATION ACTIVATED`);
    console.log(`   🎯 Target: ${threat.type.replace('_', ' ').toUpperCase()}`);
    console.log(`   🚨 Severity: ${threat.severity.toUpperCase()}`);
    console.log(`   🎯 Confidence: ${(threat.confidence * 100).toFixed(1)}%`);
    
    try {
      // Simulate mitigation actions
      if (this.config.mitigation.autoFreeze) {
        console.log(`   🥶 Action: Contract interaction freeze initiated`);
        // In a real implementation, this would interact with contracts
      }
      
      if (this.config.mitigation.emergencyPause) {
        console.log(`   ⏸️  Action: Emergency pause protocols activated`);
        // In a real implementation, this would pause affected systems
      }

      threat.mitigated = true;
      console.log(`   ✅ Mitigation completed successfully`);

      // Update social alerts with mitigation status
      await this.socialAlerts.sendAlert(threat);

    } catch (error) {
      console.error('❌ Mitigation failed:', error);
    }
  }
}