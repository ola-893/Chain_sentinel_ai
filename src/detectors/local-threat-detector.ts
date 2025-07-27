// detectors/local-threat-detector.ts
import { DetectorConfig, RealTransaction, ThreatAlert } from '../types/index';

export class LocalThreatDetector {
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