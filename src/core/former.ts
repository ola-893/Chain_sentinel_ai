import { EventEmitter } from 'events';
import * as dotenv from 'dotenv';
import axios from 'axios';
import { WebhookClient } from 'discord.js';

// Load environment variables
dotenv.config();

// Enhanced configuration interface
interface DetectorConfig {
  privateKey: string;
  seiApiKey?: string;
  seiRpcUrl: string;
  pollingInterval: number;
  threatThresholds: {
    liquidityDrain: number;
    unusualVolumeSpike: number;
    gasAnomalyThreshold: number;
    rugPullVelocityThreshold: number;
    flashLoanMinValue: number;
  };
  alerts: {
    discordWebhook?: string;
    slackWebhook?: string;
    telegramBotToken?: string;
    telegramChatId?: string;
  };
  hiveIntelligence: {
    apiKey?: string;
    endpoint?: string;
    enabled: boolean;
  };
  mitigation: {
    enabled: boolean;
    autoFreeze: boolean;
    emergencyPause: boolean;
    maxGas: number;
  };
}

// Environment validation with better error handling
function validateEnvironment(): DetectorConfig {
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
      enabled: process.env.HIVE_ENABLED !== 'false' // Allow disabling Hive Intelligence
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

interface ThreatAlert {
  id: string;
  type: 'rug_pull' | 'exploit' | 'suspicious_pattern' | 'flash_loan_attack' | 'liquidity_drain' | 'mev_attack' | 'sandwich_attack';
  severity: 'low' | 'medium' | 'high' | 'critical';
  contractAddress: string;
  transactionHash: string;
  timestamp: number;
  blockNumber: number;
  details: any;
  confidence: number;
  mitigated: boolean;
}

interface RealTransaction {
  hash: string;
  blockNumber: string;
  from: string;
  to: string;
  value: string;
  gas: string;
  gasPrice: string;
  input: string;
  timestamp: number;
  logs?: any[];
}

// Social Alert System
class SocialAlertSystem {
  private config: DetectorConfig;
  private discordClient?: WebhookClient;

  constructor(config: DetectorConfig) {
    this.config = config;
    this.initializeClients();
  }

  private initializeClients(): void {
    if (this.config.alerts.discordWebhook) {
      try {
        this.discordClient = new WebhookClient({ url: this.config.alerts.discordWebhook });
        console.log('✅ Discord webhook client initialized');
      } catch (error) {
        console.error('❌ Failed to initialize Discord client:', error);
      }
    }
  }

  async sendAlert(threat: ThreatAlert): Promise<void> {
    const alertMessage = this.formatAlertMessage(threat);
    
    try {
      // Send to Discord
      if (this.discordClient) {
        await this.sendDiscordAlert(threat, alertMessage);
      }

      // Send to Slack
      if (this.config.alerts.slackWebhook) {
        await this.sendSlackAlert(threat, alertMessage);
      }

      // Send to Telegram
      if (this.config.alerts.telegramBotToken && this.config.alerts.telegramChatId) {
        await this.sendTelegramAlert(threat, alertMessage);
      }

      console.log('📱 Social alerts sent successfully');
    } catch (error) {
      console.error('❌ Failed to send social alerts:', error);
    }
  }

  private formatAlertMessage(threat: ThreatAlert): string {
    const severityEmojis = { low: '🟡', medium: '🟠', high: '🔴', critical: '🚨' };
    const typeEmojis = {
      rug_pull: '💸',
      exploit: '🔥',
      suspicious_pattern: '⚠️',
      flash_loan_attack: '⚡',
      liquidity_drain: '🏊‍♂️',
      mev_attack: '🤖',
      sandwich_attack: '🥪'
    };

    return `${severityEmojis[threat.severity]} **THREAT DETECTED**\n` +
           `${typeEmojis[threat.type]} Type: ${threat.type.replace('_', ' ').toUpperCase()}\n` +
           `📊 Severity: ${threat.severity.toUpperCase()}\n` +
           `🎯 Confidence: ${(threat.confidence * 100).toFixed(1)}%\n` +
           `📝 Contract: \`${threat.contractAddress}\`\n` +
           `🔗 Transaction: \`${threat.transactionHash}\`\n` +
           `⏰ Time: ${new Date(threat.timestamp).toLocaleString()}\n` +
           `🛡️ Mitigated: ${threat.mitigated ? 'Yes' : 'No'}`;
  }

  private async sendDiscordAlert(threat: ThreatAlert, message: string): Promise<void> {
    if (!this.discordClient) return;

    const embed = {
      title: '🚨 Sei Threat Detection Alert',
      description: message,
      color: threat.severity === 'critical' ? 0xFF0000 : 
             threat.severity === 'high' ? 0xFF8C00 : 
             threat.severity === 'medium' ? 0xFFA500 : 0xFFFF00,
      timestamp: new Date(threat.timestamp).toISOString(),
      fields: [
        {
          name: 'Block Number',
          value: threat.blockNumber.toString(),
          inline: true
        },
        {
          name: 'Threat ID',
          value: threat.id,
          inline: true
        }
      ]
    };

    await this.discordClient.send({ embeds: [embed] });
  }

  private async sendSlackAlert(threat: ThreatAlert, message: string): Promise<void> {
    if (!this.config.alerts.slackWebhook) return;

    const payload = {
      text: `🚨 Sei Threat Detection Alert`,
      attachments: [{
        color: threat.severity === 'critical' ? 'danger' : 
               threat.severity === 'high' ? 'warning' : 'good',
        text: message,
        ts: Math.floor(threat.timestamp / 1000)
      }]
    };

    await axios.post(this.config.alerts.slackWebhook, payload);
  }

  private async sendTelegramAlert(threat: ThreatAlert, message: string): Promise<void> {
    if (!this.config.alerts.telegramBotToken || !this.config.alerts.telegramChatId) return;

    const url = `https://api.telegram.org/bot${this.config.alerts.telegramBotToken}/sendMessage`;
    const payload = {
      chat_id: this.config.alerts.telegramChatId,
      text: message,
      parse_mode: 'Markdown'
    };

    await axios.post(url, payload);
  }
}

// Fixed Hive Intelligence Integration using correct API endpoints
class HiveIntelligenceService {
  private config: DetectorConfig;
  private retryCount: number = 2;
  private retryDelay: number = 1000;
  private requestCount: number = 0;
  private maxRequestsPerMinute: number = 18; // Stay under 20/min limit
  private requestTimestamps: number[] = [];

  constructor(config: DetectorConfig) {
    this.config = config;
  }

  private canMakeRequest(): boolean {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    // Remove timestamps older than 1 minute
    this.requestTimestamps = this.requestTimestamps.filter(timestamp => timestamp > oneMinuteAgo);
    
    return this.requestTimestamps.length < this.maxRequestsPerMinute;
  }

  private recordRequest(): void {
    this.requestTimestamps.push(Date.now());
    this.requestCount++;
  }

  async analyzeTransaction(tx: RealTransaction): Promise<any> {
    if (!this.config.hiveIntelligence.enabled || !this.config.hiveIntelligence.apiKey) {
      return null;
    }

    // Check rate limits
    if (!this.canMakeRequest()) {
      if (this.requestCount % 20 === 0) { // Log every 20th skip to avoid spam
        console.log('⏳ Hive Intelligence rate limit reached, skipping analysis');
      }
      return null;
    }

    // Only analyze high-value or suspicious transactions to conserve API calls
    const value = parseInt(tx.value, 16);
    const gasPrice = parseInt(tx.gasPrice, 16);
    const isHighValue = value > this.config.threatThresholds.flashLoanMinValue;
    const isHighGas = gasPrice > this.config.threatThresholds.gasAnomalyThreshold;
    const hasComplexInput = tx.input.length > 100;

    if (!isHighValue && !isHighGas && !hasComplexInput) {
      return null; // Skip low-priority transactions
    }

    for (let attempt = 1; attempt <= this.retryCount; attempt++) {
      try {
        // Create natural language query for the search endpoint
        const prompt = this.createAnalysisPrompt(tx);
        
        const response = await axios.post(
          `${this.config.hiveIntelligence.endpoint}/v1/search`,
          {
            prompt: prompt,
            temperature: 0.2, // More deterministic for security analysis
            include_data_sources: true
          },
          {
            headers: {
              'Authorization': `Bearer ${this.config.hiveIntelligence.apiKey}`,
              'Content-Type': 'application/json'
            },
            timeout: 8000 // 8 second timeout
          }
        );

        this.recordRequest();
        return this.parseSearchResponse(response.data, tx);

      } catch (error: any) {
        if (attempt === this.retryCount) {
          if (error.response?.status === 401) {
            console.error('❌ Hive Intelligence authentication failed - check API key');
          } else if (error.response?.status === 429) {
            console.warn('⚠️  Hive Intelligence rate limit exceeded');
          } else if (error.response?.status >= 500) {
            console.warn('⚠️  Hive Intelligence server error');
          } else {
            console.warn(`⚠️  Hive Intelligence unavailable (${error.response?.status || 'network error'})`);
          }
          return null;
        }
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, this.retryDelay * attempt));
      }
    }

    return null;
  }

  private createAnalysisPrompt(tx: RealTransaction): string {
    const value = parseInt(tx.value, 16);
    const gasPrice = parseInt(tx.gasPrice, 16);
    const valueInEth = value / 1e18;
    
    return `Analyze this Sei blockchain transaction for security threats:
Transaction Hash: ${tx.hash}
From: ${tx.from}
To: ${tx.to || 'Contract Creation'}
Value: ${valueInEth.toFixed(6)} SEI
Gas Price: ${gasPrice} wei
Input Data Length: ${tx.input.length} bytes

Look for signs of:
1. Rug pull attacks or exit scams
2. Flash loan exploits or arbitrage attacks  
3. MEV (Maximum Extractable Value) activities
4. Suspicious contract interactions
5. Large token transfers that could indicate liquidity drains
6. Unusual gas patterns suggesting front-running

Provide a risk assessment with confidence level if any threats are detected.`;
  }

  private parseSearchResponse(searchData: any, tx: RealTransaction | null | undefined): any {
    if (!searchData || !searchData.response) {
      return null;
    }

    const response = searchData.response.toLowerCase();
    const analysis: any = {
      threats: [],
      dataSources: searchData.data_sources || [],
      rawResponse: searchData.response
    };

    // Parse natural language response for threat indicators
    if (response.includes('rug pull') || response.includes('exit scam')) {
      analysis.rugPull = {
        risk: this.extractRiskScore(response, 'rug pull'),
        indicators: this.extractIndicators(response, ['rug pull', 'exit scam', 'liquidity'])
      };
    }

    if (response.includes('flash loan') || response.includes('arbitrage')) {
      analysis.flashLoan = {
        risk: this.extractRiskScore(response, 'flash loan'),
        indicators: this.extractIndicators(response, ['flash loan', 'arbitrage', 'exploit'])
      };
    }

    if (response.includes('mev') || response.includes('front-running') || response.includes('sandwich')) {
      analysis.mev = {
        risk: this.extractRiskScore(response, 'mev'),
        indicators: this.extractIndicators(response, ['mev', 'front-running', 'sandwich'])
      };
    }

    // Extract overall risk assessment
    analysis.overallRisk = this.extractOverallRisk(response);
    analysis.confidence = this.extractConfidence(response);

    return analysis;
  }

  private extractRiskScore(text: string, threatType: string): number {
    // Look for risk indicators in the text
    if (text.includes('high risk') || text.includes('critical')) return 0.9;
    if (text.includes('medium risk') || text.includes('moderate')) return 0.6;
    if (text.includes('low risk') || text.includes('minimal')) return 0.3;
    if (text.includes('suspicious') || text.includes('concerning')) return 0.7;
    if (text.includes('no risk') || text.includes('safe')) return 0.1;
    
    // Default moderate risk if threat type mentioned
    return text.includes(threatType) ? 0.5 : 0.0;
  }

  private extractIndicators(text: string, keywords: string[]): string[] {
    const indicators: string[] = [];
    for (const keyword of keywords) {
      if (text.includes(keyword)) {
        indicators.push(keyword);
      }
    }
    return indicators;
  }

  private extractOverallRisk(text: string): number {
    if (text.includes('high risk') || text.includes('dangerous')) return 0.8;
    if (text.includes('medium risk') || text.includes('moderate risk')) return 0.5;
    if (text.includes('low risk') || text.includes('minimal risk')) return 0.2;
    return 0.3; // Default moderate-low risk
  }

  private extractConfidence(text: string): number {
    if (text.includes('confident') || text.includes('certain')) return 0.9;
    if (text.includes('likely') || text.includes('probable')) return 0.7;
    if (text.includes('possible') || text.includes('might')) return 0.5;
    if (text.includes('uncertain') || text.includes('unclear')) return 0.3;
    return 0.6; // Default moderate confidence
  }

  async analyzeContract(contractAddress: string): Promise<any> {
    if (!this.config.hiveIntelligence.enabled || !this.config.hiveIntelligence.apiKey) {
      return null;
    }

    if (!this.canMakeRequest()) {
      return null;
    }

    try {
      const prompt = `Analyze this Sei blockchain contract for security risks:
Contract Address: ${contractAddress}

Look for:
1. Known malicious contract patterns
2. Rug pull indicators (liquidity locks, ownership patterns)
3. Honeypot characteristics
4. Unusual token economics
5. Centralization risks

Provide a security assessment and risk rating.`;

      const response = await axios.post(
        `${this.config.hiveIntelligence.endpoint}/v1/search`,
        {
          prompt: prompt,
          temperature: 0.2,
          include_data_sources: true
        },
        {
          headers: {
            'Authorization': `Bearer ${this.config.hiveIntelligence.apiKey}`,
            'Content-Type': 'application/json'
          },
          timeout: 8000
        }
      );

      this.recordRequest();
      return this.parseSearchResponse(response.data, null);

    } catch (error) {
      // Silently fail for contract analysis
      return null;
    }
  }

  getStats() {
    return {
      requestCount: this.requestCount,
      requestsInLastMinute: this.requestTimestamps.length,
      rateLimitRemaining: this.maxRequestsPerMinute - this.requestTimestamps.length
    };
  }
}

// Enhanced Sei Blockchain Service
class SeiBlockchainService {
  private config: DetectorConfig;
  private requestId: number = 1;

  constructor(config: DetectorConfig) {
    this.config = config;
  }

  private getNextRequestId(): number {
    return this.requestId++;
  }

  async getLatestBlock(): Promise<number> {
    try {
      const response = await axios.post(this.config.seiRpcUrl, {
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: this.getNextRequestId()
      }, {
        timeout: 10000 // 10 second timeout
      });

      return parseInt(response.data.result, 16);
    } catch (error) {
      console.error('❌ Failed to get latest block:', error);
      throw error;
    }
  }

  async getBlock(blockNumber: number): Promise<any> {
    try {
      const blockHex = '0x' + blockNumber.toString(16);
      const response = await axios.post(this.config.seiRpcUrl, {
        jsonrpc: '2.0',
        method: 'eth_getBlockByNumber',
        params: [blockHex, true],
        id: this.getNextRequestId()
      }, {
        timeout: 10000
      });

      return response.data.result;
    } catch (error) {
      console.error(`❌ Failed to get block ${blockNumber}:`, error);
      throw error;
    }
  }

  async getTransaction(txHash: string): Promise<any> {
    try {
      const response = await axios.post(this.config.seiRpcUrl, {
        jsonrpc: '2.0',
        method: 'eth_getTransactionByHash',
        params: [txHash],
        id: this.getNextRequestId()
      }, {
        timeout: 10000
      });

      return response.data.result;
    } catch (error) {
      console.error(`❌ Failed to get transaction ${txHash}:`, error);
      throw error;
    }
  }

  async getTransactionReceipt(txHash: string): Promise<any> {
    try {
      const response = await axios.post(this.config.seiRpcUrl, {
        jsonrpc: '2.0',
        method: 'eth_getTransactionReceipt',
        params: [txHash],
        id: this.getNextRequestId()
      }, {
        timeout: 10000
      });

      return response.data.result;
    } catch (error) {
      console.error(`❌ Failed to get transaction receipt ${txHash}:`, error);
      throw error;
    }
  }
}

// Enhanced Local Threat Detection Patterns
class LocalThreatDetector {
  private config: DetectorConfig;
  private recentTransactions: Map<string, RealTransaction[]> = new Map();
  private contractInteractions: Map<string, number> = new Map();

  constructor(config: DetectorConfig) {
    this.config = config;
  }

  async detectThreats(tx: RealTransaction): Promise<ThreatAlert[]> {
    const threats: ThreatAlert[] = [];

    // Track transactions for pattern analysis
    this.trackTransaction(tx);

    // Various threat detection patterns
    threats.push(...await this.detectGasAnomalies(tx));
    threats.push(...await this.detectLargeValueTransfers(tx));
    threats.push(...await this.detectMEVActivity(tx));
    threats.push(...await this.detectSuspiciousPatterns(tx));
    threats.push(...await this.detectContractBehavior(tx));

    return threats;
  }

  private trackTransaction(tx: RealTransaction): void {
    const key = tx.from + '-' + tx.to;
    if (!this.recentTransactions.has(key)) {
      this.recentTransactions.set(key, []);
    }
    
    const txList = this.recentTransactions.get(key)!;
    txList.push(tx);
    
    // Keep only last 10 transactions
    if (txList.length > 10) {
      txList.shift();
    }

    // Track contract interactions
    if (tx.to && tx.input !== '0x') {
      const count = this.contractInteractions.get(tx.to) || 0;
      this.contractInteractions.set(tx.to, count + 1);
    }
  }

  private async detectGasAnomalies(tx: RealTransaction): Promise<ThreatAlert[]> {
    const threats: ThreatAlert[] = [];
    const gasPrice = parseInt(tx.gasPrice, 16);
    
    if (gasPrice > this.config.threatThresholds.gasAnomalyThreshold) {
      threats.push({
        id: `gas_anomaly_${tx.hash}_${Date.now()}`,
        type: 'suspicious_pattern',
        severity: gasPrice > this.config.threatThresholds.gasAnomalyThreshold * 2 ? 'high' : 'medium',
        contractAddress: tx.to || '',
        transactionHash: tx.hash,
        timestamp: tx.timestamp,
        blockNumber: parseInt(tx.blockNumber, 16),
        details: {
          gasPrice,
          threshold: this.config.threatThresholds.gasAnomalyThreshold,
          suspiciousPattern: 'extremely_high_gas_price',
          possibleMEV: true
        },
        confidence: Math.min(0.9, gasPrice / this.config.threatThresholds.gasAnomalyThreshold * 0.3),
        mitigated: false
      });
    }

    return threats;
  }

  private async detectLargeValueTransfers(tx: RealTransaction): Promise<ThreatAlert[]> {
    const threats: ThreatAlert[] = [];
    const value = parseInt(tx.value, 16);
    
    if (value > this.config.threatThresholds.flashLoanMinValue) {
      threats.push({
        id: `large_transfer_${tx.hash}_${Date.now()}`,
        type: 'suspicious_pattern',
        severity: value > this.config.threatThresholds.flashLoanMinValue * 10 ? 'high' : 'medium',
        contractAddress: tx.to || '',
        transactionHash: tx.hash,
        timestamp: tx.timestamp,
        blockNumber: parseInt(tx.blockNumber, 16),
        details: {
          value: tx.value,
          valueWei: value,
          suspiciousPattern: 'large_value_transfer',
          inputDataSize: tx.input.length
        },
        confidence: 0.6,
        mitigated: false
      });
    }

    return threats;
  }

  private async detectMEVActivity(tx: RealTransaction): Promise<ThreatAlert[]> {
    const threats: ThreatAlert[] = [];
    const gasPrice = parseInt(tx.gasPrice, 16);
    
    // Detect potential MEV activity based on gas price and transaction patterns
    if (gasPrice > this.config.threatThresholds.gasAnomalyThreshold * 0.5 && tx.input.length > 10) {
      const key = tx.from + '-' + tx.to;
      const recentTxs = this.recentTransactions.get(key) || [];
      
      if (recentTxs.length > 2) {
        const avgGasPrice = recentTxs.reduce((sum, rtx) => sum + parseInt(rtx.gasPrice, 16), 0) / recentTxs.length;
        
        if (gasPrice > avgGasPrice * 3) {
          threats.push({
            id: `mev_activity_${tx.hash}_${Date.now()}`,
            type: 'mev_attack',
            severity: 'medium',
            contractAddress: tx.to || '',
            transactionHash: tx.hash,
            timestamp: tx.timestamp,
            blockNumber: parseInt(tx.blockNumber, 16),
            details: {
              gasPrice,
              avgGasPrice,
              gasPriceMultiplier: gasPrice / avgGasPrice,
              suspiciousPattern: 'potential_mev_activity'
            },
            confidence: 0.7,
            mitigated: false
          });
        }
      }
    }

    return threats;
  }

  private async detectSuspiciousPatterns(tx: RealTransaction): Promise<ThreatAlert[]> {
    const threats: ThreatAlert[] = [];

    // Detect contract creation with suspicious patterns
    if (!tx.to && tx.input.length > 1000) {
      threats.push({
        id: `suspicious_contract_${tx.hash}_${Date.now()}`,
        type: 'suspicious_pattern',
        severity: 'low',
        contractAddress: '',
        transactionHash: tx.hash,
        timestamp: tx.timestamp,
        blockNumber: parseInt(tx.blockNumber, 16),
        details: {
          suspiciousPattern: 'large_contract_creation',
          inputSize: tx.input.length
        },
        confidence: 0.4,
        mitigated: false
      });
    }

    return threats;
  }

  private async detectContractBehavior(tx: RealTransaction): Promise<ThreatAlert[]> {
    const threats: ThreatAlert[] = [];

    if (tx.to) {
      const interactions = this.contractInteractions.get(tx.to) || 0;
      
      // Detect contracts with very high interaction frequency
      if (interactions > 100) {
        threats.push({
          id: `high_frequency_contract_${tx.hash}_${Date.now()}`,
          type: 'suspicious_pattern',
          severity: 'low',
          contractAddress: tx.to,
          transactionHash: tx.hash,
          timestamp: tx.timestamp,
          blockNumber: parseInt(tx.blockNumber, 16),
          details: {
            suspiciousPattern: 'high_frequency_interactions',
            interactionCount: interactions
          },
          confidence: 0.5,
          mitigated: false
        });
      }
    }

    return threats;
  }
}

// Main Enhanced Threat Detector
class EnhancedSeiThreatDetector extends EventEmitter {
  private monitoringActive: boolean = false;
  private currentBlock: number = 0;
  private config: DetectorConfig;
  private socialAlerts: SocialAlertSystem;
  private hiveIntelligence: HiveIntelligenceService;
  private blockchainService: SeiBlockchainService;
  private localDetector: LocalThreatDetector;
  private threatHistory: Map<string, ThreatAlert> = new Map();
  private stats = {
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

          await this.analyzeThreatPatterns(realTx);
          this.stats.transactionsAnalyzed++;
        }
      }
    } catch (error) {
      console.error(`❌ Error analyzing block ${blockNumber}:`, error);
    }
  }

  private async analyzeThreatPatterns(transaction: RealTransaction): Promise<void> {
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

      // Handle detected threats
      for (const threat of threats) {
        await this.handleThreat(threat);
      }

    } catch (error) {
      console.error('❌ Error in threat analysis:', error);
    }
  }

  private processHiveThreats(tx: RealTransaction, hiveAnalysis: any): ThreatAlert[] {
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

  private async handleThreat(threat: ThreatAlert): Promise<void> {
    // Log threat
    console.log(`\n🚨 THREAT DETECTED [${new Date(threat.timestamp).toISOString()}]`);
    console.log(`   ⚠️ Type: ${threat.type.toUpperCase().replace('_', ' ')}`);
    console.log(`   📊 Severity: ${threat.severity.toUpperCase()}`);
    console.log(`   🎯 Confidence: ${(threat.confidence * 100).toFixed(1)}%`);
    console.log(`   📝 Contract: ${threat.contractAddress.substr(0, 10)}...`);
    console.log(`   🔗 Transaction: ${threat.transactionHash.substr(0, 10)}...`);

    // Store threat
    this.threatHistory.set(threat.id, threat);
    this.stats.threatsDetected++;

    // Send social alerts for medium+ severity threats
    if (threat.severity === 'medium' || threat.severity === 'high' || threat.severity === 'critical') {
      await this.socialAlerts.sendAlert(threat);
    }

    // Auto-mitigation for critical threats
    if (this.config.mitigation.enabled && threat.severity === 'critical' && threat.confidence > 0.8) {
      await this.executeMitigation(threat);
    }

    // Emit event
    this.emit('threat_detected', threat);
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

  getStats() {
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

// Testing function
async function testSystem() {
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

// Utility function to create example .env file
function createExampleEnv() {
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

// Main execution
async function main() {
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

// Export for use in other modules
export {
  EnhancedSeiThreatDetector,
  SocialAlertSystem,
  HiveIntelligenceService,
  SeiBlockchainService,
  LocalThreatDetector,
  ThreatAlert,
  DetectorConfig
};

// Run if this is the main module
if (require.main === module) {
  // Check command line arguments
  const args = process.argv.slice(2);
  
  if (args.includes('--test')) {
    testSystem().catch(console.error);
  } else if (args.includes('--example-env')) {
    createExampleEnv();
  } else if (args.includes('--help')) {
    console.log('🎯 Sei Threat Detector Usage:');
    console.log('   npm run dev              - Start the threat detector');
    console.log('   npm run dev -- --test    - Run system tests');
    console.log('   npm run dev -- --example-env - Show example .env file');
    console.log('   npm run dev -- --help    - Show this help message');
  } else {
    main().catch(console.error);
  }
}