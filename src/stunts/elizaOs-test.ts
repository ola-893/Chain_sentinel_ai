// eliza-integration.ts
import { Plugin } from '@elizaos/core';
import { seiPlugin } from '@elizaos/plugin-sei';
import { EnhancedSeiThreatDetector, ThreatAlert } from './enhanced-detector';

interface ElizaConfig {
  rpcUrl: string;
  privateKey: string;
  chainId?: string;
  modelProvider?: string;
}

class ElizaSeiThreatAgent {
  private detector: EnhancedSeiThreatDetector;
  private elizaPlugin: Plugin;
  private isInitialized: boolean = false;

  constructor(detector: EnhancedSeiThreatDetector) {
    this.detector = detector;
  }

  async initialize(config: ElizaConfig): Promise<void> {
    try {
      console.log('🤖 Initializing ElizaOS Sei Plugin...');
      
      // Initialize the Sei plugin
      this.elizaPlugin = seiPlugin;
      
      // Configure the plugin with Sei network settings
      await this.elizaPlugin.initialize({
        rpcUrl: config.rpcUrl,
        privateKey: config.privateKey,
        chainId: config.chainId || 'sei-mainnet',
        modelProvider: config.modelProvider || 'openai'
      });

      // Set up event listeners
      this.setupEventListeners();
      
      this.isInitialized = true;
      console.log('✅ ElizaOS Sei Plugin initialized successfully');
    } catch (error) {
      console.error('❌ Failed to initialize ElizaOS Plugin:', error);
      throw error;
    }
  }

  private setupEventListeners(): void {
    // Listen for threat detection events
    this.detector.on('threat_detected', async (threat: ThreatAlert) => {
      await this.handleThreatWithEliza(threat);
    });

    // Listen for mitigation events
    this.detector.on('mitigation_executed', async (threat: ThreatAlert) => {
      await this.reportMitigationToEliza(threat);
    });
  }

  private async handleThreatWithEliza(threat: ThreatAlert): Promise<void> {
    if (!this.isInitialized) return;

    try {
      console.log('🤖 Processing threat with ElizaOS...');

      // Use ElizaOS to analyze the threat context
      const contextAnalysis = await this.analyzeContextWithEliza(threat);
      
      // Generate intelligent response based on threat type
      const response = await this.generateThreatResponse(threat, contextAnalysis);
      
      // Execute enhanced actions through ElizaOS
      await this.executeElizaActions(threat, response);

    } catch (error) {
      console.error('❌ ElizaOS threat handling failed:', error);
    }
  }

  private async analyzeContextWithEliza(threat: ThreatAlert): Promise<any> {
    // Use ElizaOS to gather additional context about the threat
    const contextPrompt = `
      Analyze this blockchain threat:
      Type: ${threat.type}
      Severity: ${threat.severity}
      Contract: ${threat.contractAddress}
      Transaction: ${threat.transactionHash}
      Confidence: ${threat.confidence}
      
      Provide context about:
      1. Similar historical patterns
      2. Contract reputation
      3. Risk assessment
      4. Recommended actions
    `;

    try {
      const analysis = await this.elizaPlugin.generateResponse({
        prompt: contextPrompt,
        context: {
          threat: threat,
          chainId: 'sei-mainnet'
        }
      });

      return analysis;
    } catch (error) {
      console.error('❌ Context analysis failed:', error);
      return null;
    }
  }

  private async generateThreatResponse(threat: ThreatAlert, context: any): Promise<string> {
    const responsePrompt = `
      Based on the threat analysis and context, generate a comprehensive response for:
      
      Threat: ${threat.type} (${threat.severity})
      Context: ${JSON.stringify(context, null, 2)}
      
      Include:
      1. Immediate actions needed
      2. Stakeholder notifications
      3. Technical mitigation steps
      4. Follow-up monitoring
      
      Format as actionable intelligence.
    `;

    try {
      const response = await this.elizaPlugin.generateResponse({
        prompt: responsePrompt,
        context: { threat, analysis: context }
      });

      return response;
    } catch (error) {
      console.error('❌ Response generation failed:', error);
      return `Standard response for ${threat.type} threat detected.`;
    }
  }

  private async executeElizaActions(threat: ThreatAlert, response: string): Promise<void> {
    console.log('🤖 ElizaOS Threat Response:');
    console.log('=' .repeat(50));
    console.log(response);
    console.log('=' .repeat(50));

    // Execute specific actions based on threat type
    switch (threat.type) {
      case 'rug_pull':
        await this.handleRugPullWithEliza(threat);
        break;
      case 'flash_loan_attack':
        await this.handleFlashLoanWithEliza(threat);
        break;
      case 'exploit':
        await this.handleExploitWithEliza(threat);
        break;
      case 'suspicious_pattern':
        await this.handleSuspiciousActivityWithEliza(threat);
        break;
    }
  }

  private async handleRugPullWithEliza(threat: ThreatAlert): Promise<void> {
    console.log('🤖 ElizaOS: Executing rug pull mitigation protocol');
    
    try {
      // Use ElizaOS to interact with Sei contracts
      await this.elizaPlugin.executeAction({
        action: 'emergency_pause',
        contractAddress: threat.contractAddress,
        reason: 'Rug pull detected',
        gasLimit: 500000
      });

      // Generate stakeholder alert
      const alertMessage = await this.generateStakeholderAlert(threat);
      console.log('📧 Stakeholder alert generated:', alertMessage);

    } catch (error) {
      console.error('❌ Rug pull mitigation failed:', error);
    }
  }

  private async handleFlashLoanWithEliza(threat: ThreatAlert): Promise<void> {
    console.log('🤖 ElizaOS: Implementing flash loan attack countermeasures');
    
    try {
      // Circuit breaker activation
      await this.elizaPlugin.executeAction({
        action: 'circuit_breaker',
        contractAddress: threat.contractAddress,
        duration: '1h',
        reason: 'Flash loan attack detected'
      });

    } catch (error) {
      console.error('❌ Flash loan mitigation failed:', error);
    }
  }

  private async handleExploitWithEliza(threat: ThreatAlert): Promise<void> {
    console.log('🤖 ElizaOS: Activating exploit defense measures');
    
    try {
      // Immediate contract interaction pause
      await this.elizaPlugin.executeAction({
        action: 'pause_interactions',
        contractAddress: threat.contractAddress,
        emergency: true
      });

      // Deep analysis request
      await this.requestDeepAnalysis(threat);

    } catch (error) {
      console.error('❌ Exploit mitigation failed:', error);
    }
  }

  private async handleSuspiciousActivityWithEliza(threat: ThreatAlert): Promise<void> {
    console.log('🤖 ElizaOS: Monitoring suspicious activity pattern');
    
    try {
      // Enhanced monitoring
      await this.elizaPlugin.executeAction({
        action: 'enhance_monitoring',
        contractAddress: threat.contractAddress,
        duration: '24h',
        alertThreshold: 0.5
      });

    } catch (error) {
      console.error('❌ Suspicious activity handling failed:', error);
    }
  }

  private async generateStakeholderAlert(threat: ThreatAlert): Promise<string> {
    const alertPrompt = `Generate a professional stakeholder alert for this threat:
    
    Type: ${threat.type}
    Severity: ${threat.severity}
    Contract: ${threat.contractAddress}
    Confidence: ${(threat.confidence * 100).toFixed(1)}%
    
    The alert should be:
    1. Professional and clear
    2. Include immediate actions taken
    3. Provide next steps
    4. Be suitable for executive communication
    `;

    try {
      return await this.elizaPlugin.generateResponse({
        prompt: alertPrompt,
        context: { threat }
      });
    } catch (error) {
      return `URGENT: ${threat.type} detected on contract ${threat.contractAddress}. Immediate review required.`;
    }
  }

  private async requestDeepAnalysis(threat: ThreatAlert): Promise<void> {
    console.log('🔍 Requesting deep analysis from ElizaOS...');
    
    try {
      const analysisRequest = {
        threatId: threat.id,
        contractAddress: threat.contractAddress,
        transactionHash: threat.transactionHash,
        analysisType: 'comprehensive',
        priority: 'high'
      };

      await this.elizaPlugin.executeAction({
        action: 'request_analysis',
        ...analysisRequest
      });

    } catch (error) {
      console.error('❌ Deep analysis request failed:', error);
    }
  }

  private async reportMitigationToEliza(threat: ThreatAlert): Promise<void> {
    console.log('🤖 Reporting mitigation success to ElizaOS...');
    
    try {
      const report = await this.elizaPlugin.generateResponse({
        prompt: `Generate a mitigation success report for:
        Threat ID: ${threat.id}
        Type: ${threat.type}
        Mitigation: ${threat.mitigated ? 'Successful' : 'Failed'}
        
        Include lessons learned and prevention strategies.`,
        context: { threat }
      });

      console.log('📊 Mitigation Report:');
      console.log(report);

    } catch (error) {
      console.error('❌ Mitigation reporting failed:', error);
    }
  }

  // Public API for manual intervention
  async manualAnalysis(contractAddress: string): Promise<string> {
    if (!this.isInitialized) {
      throw new Error('ElizaOS plugin not initialized');
    }

    const analysisPrompt = `Perform a comprehensive security analysis of Sei contract: ${contractAddress}
    
    Include:
    1. Code audit summary
    2. Risk assessment
    3. Vulnerability scan results
    4. Recommendations
    `;

    try {
      return await this.elizaPlugin.generateResponse({
        prompt: analysisPrompt,
        context: { contractAddress, chainId: 'sei-mainnet' }
      });
    } catch (error) {
      console.error('❌ Manual analysis failed:', error);
      throw error;
    }
  }

  async getContractReputation(contractAddress: string): Promise<any> {
    try {
      return await this.elizaPlugin.executeAction({
        action: 'get_reputation',
        contractAddress: contractAddress,
        includeHistory: true
      });
    } catch (error) {
      console.error('❌ Reputation check failed:', error);
      return null;
    }
  }
}

// Enhanced detector with ElizaOS integration
class ElizaEnhancedSeiThreatDetector extends EnhancedSeiThreatDetector {
  private elizaAgent: ElizaSeiThreatAgent;

  constructor(config: any) {
    super(config);
    this.elizaAgent = new ElizaSeiThreatAgent(this);
  }

  async start(): Promise<void> {
    // Initialize ElizaOS first
    await this.elizaAgent.initialize({
      rpcUrl: this.config.seiRpcUrl,
      privateKey: this.config.privateKey,
      chainId: 'sei-mainnet'
    });

    // Then start the main detector
    await super.start();
    
    console.log('🤖 ElizaOS-enhanced threat detection active!');
  }

  // Expose ElizaOS capabilities
  async analyzeContract(contractAddress: string): Promise<string> {
    return await this.elizaAgent.manualAnalysis(contractAddress);
  }

  async getContractRisk(contractAddress: string): Promise<any> {
    return await this.elizaAgent.getContractReputation(contractAddress);
  }
}

// Usage example
async function runElizaEnhancedDetector() {
  const config = {
    // ... your existing config
    enableEliza: true
  };

  const detector = new ElizaEnhancedSeiThreatDetector(config);
  
  // Manual contract analysis
  detector.on('threat_detected', async (threat) => {
    if (threat.severity === 'critical') {
      console.log('🤖 Running additional ElizaOS analysis...');
      const analysis = await detector.analyzeContract(threat.contractAddress);
      console.log('🧠 ElizaOS Analysis:', analysis);
    }
  });

  await detector.start();
}

export {
  ElizaSeiThreatAgent,
  ElizaEnhancedSeiThreatDetector,
  runElizaEnhancedDetector
};