// types/index.ts
export interface DetectorConfig {
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

export interface ThreatAlert {
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

export interface RealTransaction {
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

export interface HiveAnalysis {
  threats: any[];
  dataSources: any[];
  rawResponse: string;
  rugPull?: {
    risk: number;
    indicators: string[];
  };
  flashLoan?: {
    risk: number;
    indicators: string[];
  };
  mev?: {
    risk: number;
    indicators: string[];
  };
  overallRisk: number;
  confidence: number;
}

export interface DetectorStats {
  blocksProcessed: number;
  transactionsAnalyzed: number;
  threatsDetected: number;
  startTime: number;
  uptime?: number;
  currentBlock?: number;
  isMonitoring?: boolean;
  hiveIntelligence?: {
    requestCount: number;
    requestsInLastMinute: number;
    rateLimitRemaining: number;
  };
}