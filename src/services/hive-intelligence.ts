// services/hive-intelligence.ts
import axios from 'axios';
import { DetectorConfig, RealTransaction, HiveAnalysis } from '../types/index';

export class HiveIntelligenceService {
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

  async analyzeTransaction(tx: RealTransaction): Promise<HiveAnalysis | null> {
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

  private parseSearchResponse(searchData: any, tx: RealTransaction | null | undefined): HiveAnalysis | null {
    if (!searchData || !searchData.response) {
      return null;
    }

    const response = searchData.response.toLowerCase();
    const analysis: HiveAnalysis = {
      threats: [],
      dataSources: searchData.data_sources || [],
      rawResponse: searchData.response,
      overallRisk: this.extractOverallRisk(response),
      confidence: this.extractConfidence(response)
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

  async analyzeContract(contractAddress: string): Promise<HiveAnalysis | null> {
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