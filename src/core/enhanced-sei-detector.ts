// core/enhanced-sei-detector.ts
import { EventEmitter } from 'events';
import { DetectorConfig, RealTransaction, ThreatAlert, DetectorStats } from '../types/index';
import { SeiBlockchainService } from '../services/blockchain';
import { SocialAlertSystem } from '../services/alerts';
import { HiveIntelligenceService } from '../services/hive-intelligence';
import { LocalThreatDetector } from '../detectors/local-threat-detector';
import { ThreatProcessor } from '../detectors/threat-processor';

export class EnhancedSeiThreatDetector extends EventEmitter {
  private monitoringActive: boolean = false;
  private currentBlock: number = 0;
  private config: DetectorConfig;
  private socialAlerts: SocialAlertSystem;
  private hiveIntelligence: HiveIntelligenceService;
  private blockchainService: SeiBlockchainService;
  private localDetector: LocalThreatDetector;
  private threatProcessor: ThreatProcessor;
  private threatHistory: Map<string, ThreatAlert> = new Map();
  private stats: DetectorStats = {
    blocksProcessed: 0,
    transactionsAnalyzed: 0,
    threatsDetected: 0,
    startTime: Date.now()
  };

  constructor(config: DetectorConfig) {
    super();
    this.config = config;
    this.socialAlerts = new SocialAlertSystem(config);
    this.hiveIntelligence = new HiveIntelligenceService(config);
    this.blockchainService = new SeiBlockchainService(config);
    this.localDetector = new LocalThreatDetector(config);
    this.threatProcessor = new ThreatProcessor(
      config,
      this.localDetector,
      this.hiveIntelligence,
      this.socialAlerts
    );
  }

  async start(): Promise<void> {
    console.log('🚀 Starting Enhanced Sei Threat Detection Agent...');
    console.log('📡 Connecting to real Sei blockchain data');
    
    try {
      // Get current block number
      this.currentBlock = await this.blockchainService.getLatestBlock();
      console.log(`📊 Starting monitoring at block ${this.currentBlock}`);
      
      this.monitoringActive = true;
      this.stats.startTime = Date.now();
      this.startMonitoring();
      this.startStatsReporting();
      
      console.log('✅ Enhanced threat detection agent active');
    } catch (error) {
      console.error('❌ Failed to start monitoring:', error);
      throw error;
    }
  }

  private startStatsReporting(): void {
    // Report stats every 5 minutes
    setInterval(() => {
      const uptime = Math.round((Date.now() - this.stats.startTime) / 1000);
      const rate = this.stats.transactionsAnalyzed / (uptime / 60); // per minute
      
      console.log(`\n📊 STATS REPORT [Uptime: ${uptime}s]`);
      console.log(`   📦 Blocks processed: ${this.stats.blocksProcessed}`);
      console.log(`   🔍 Transactions analyzed: ${this.stats.transactionsAnalyzed}`);
      console.log(`   🚨 Threats detected: ${this.stats.threatsDetected}`);
      console.log(`   ⚡ Analysis rate: ${rate.toFixed(1)} tx/min\n`);
    }, 300000); // 5 minutes
  }

  private startMonitoring(): void {
    const monitorLoop = async () => {
      if (!this.monitoringActive) return;

      try {
        const startTime = Date.now();
        
        // Check for new blocks
        const latestBlock = await this.blockchainService.getLatestBlock();
        
        if (latestBlock > this.currentBlock) {
          // Process all new blocks
          for (let blockNum = this.currentBlock + 1; blockNum <= latestBlock; blockNum++) {
            await this.analyzeBlock(blockNum);
            this.stats.blocksProcessed++;
          }
          this.currentBlock = latestBlock;
        }

        const processingTime = Date.now() - startTime;
        
        // Dynamic polling interval based on processing time
        const nextPoll = Math.max(100, this.config.pollingInterval - processingTime);
        setTimeout(monitorLoop, nextPoll);

      } catch (error) {
        console.error('❌ Monitoring error:', error);
        setTimeout(monitorLoop, 2000); // Retry after 2 seconds on error
      }
    };

    monitorLoop();
  }

  private async analyzeBlock(blockNumber: number): Promise<void> {
    try {
      const block = await this.blockchainService.getBlock(blockNumber);
      
      if (!block || !block.transactions) {
        return;
      }

      console.log(`📦 Block ${blockNumber}: Analyzing ${block.transactions.length} transactions`);

      // Analyze each transaction
      for (const tx of block.transactions) {
        if (typeof tx === 'object' && tx.hash) {
          const realTx: RealTransaction = {
            hash: tx.hash,
            blockNumber: tx.blockNumber,
            from: tx.from,
            to: tx.to,
            value: tx.value,
            gas: tx.gas,
            gasPrice: tx.gasPrice,
            input: tx.input,
            timestamp: parseInt(block.timestamp, 16) * 1000
          };

          await this.processTransaction(realTx);
          this.stats.transactionsAnalyzed++;
        }
      }
    } catch (error) {
      console.error(`❌ Error analyzing block ${blockNumber}:`, error);
    }
  }

  private async processTransaction(transaction: RealTransaction): Promise<void> {
    try {
      const threats = await this.threatProcessor.analyzeThreatPatterns(transaction);

      // Handle detected threats
      for (const threat of threats) {
        await this.handleThreat(threat);
      }
    } catch (error) {
      console.error('❌ Error processing transaction:', error);
    }
  }

  private async handleThreat(threat: ThreatAlert): Promise<void> {
    // Store threat
    this.threatHistory.set(threat.id, threat);
    this.stats.threatsDetected++;

    // Process the threat
    await this.threatProcessor.handleThreat(threat);

    // Emit event
    this.emit('threat_detected', threat);
  }

  async stop(): Promise<void> {
    console.log('\n🛑 Stopping enhanced threat detection agent...');
    this.monitoringActive = false;
    
    // Print final statistics
    const uptime = Math.round((Date.now() - this.stats.startTime) / 1000);
    console.log(`\n📊 FINAL STATISTICS`);
    console.log(`   ⏱️  Total uptime: ${uptime} seconds`);
    console.log(`   📦 Blocks processed: ${this.stats.blocksProcessed}`);
    console.log(`   🔍 Transactions analyzed: ${this.stats.transactionsAnalyzed}`);
    console.log(`   🚨 Total threats detected: ${this.stats.threatsDetected}`);
    console.log(`   ⚡ Average rate: ${(this.stats.transactionsAnalyzed / (uptime / 60)).toFixed(1)} tx/min`);
    console.log('✅ Enhanced threat detection agent stopped');
  }

  // Public API methods
  async testAlerts(): Promise<void> {
    console.log('🧪 Testing alert systems...');
    
    const testThreat: ThreatAlert = {
      id: `test_threat_${Date.now()}`,
      type: 'suspicious_pattern',
      severity: 'medium',
      contractAddress: '0x1234567890123456789012345678901234567890',
      transactionHash: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef',
      timestamp: Date.now(),
      blockNumber: 12345,
      details: { 
        test: true,
        suspiciousPattern: 'test_alert',
        description: 'This is a test alert to verify the alerting system'
      },
      confidence: 0.75,
      mitigated: false
    };

    await this.socialAlerts.sendAlert(testThreat);
    console.log('✅ Test alerts sent');
  }

  getThreatHistory(): ThreatAlert[] {
    return Array.from(this.threatHistory.values());
  }

  getStats(): DetectorStats {
    const hiveStats = this.hiveIntelligence.getStats();
    return {
      ...this.stats,
      uptime: Date.now() - this.stats.startTime,
      currentBlock: this.currentBlock,
      isMonitoring: this.monitoringActive,
      hiveIntelligence: hiveStats
    };
  }

  // Method to add custom threat patterns
  addCustomThreatPattern(pattern: (tx: RealTransaction) => Promise<ThreatAlert[]>): void {
    // This could be extended to allow custom threat detection patterns
    console.log('📝 Custom threat pattern registered');
  }
}

export {
  SocialAlertSystem,
  HiveIntelligenceService,
  SeiBlockchainService,
  LocalThreatDetector,
  ThreatProcessor
};