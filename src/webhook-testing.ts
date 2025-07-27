import * as dotenv from 'dotenv';
import fetch from 'node-fetch';

dotenv.config();

interface TestThreat {
  type: string;
  severity: string;
  contractAddress: string;
  transactionHash: string;
  timestamp: number;
  confidence: number;
  details: any;
}

class WebhookTester {
  private config = {
    discord: process.env.DISCORD_WEBHOOK,
    slack: process.env.SLACK_WEBHOOK,
    telegram: process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID ? {
      botToken: process.env.TELEGRAM_BOT_TOKEN,
      chatId: process.env.TELEGRAM_CHAT_ID
    } : null
  };

  async testAllWebhooks(): Promise<void> {
    console.log('🧪 Testing all webhook integrations...\n');

    const testThreat: TestThreat = {
      type: 'rug_pull',
      severity: 'critical',
      contractAddress: '0x1234567890123456789012345678901234567890',
      transactionHash: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef',
      timestamp: Date.now(),
      confidence: 0.95,
      details: {
        value: '50000000000000000000',
        gasPrice: 250000000000,
        suspiciousPattern: 'large_value_drain',
        riskScore: 85
      }
    };

    // Test Discord
    if (this.config.discord) {
      console.log('📧 Testing Discord webhook...');
      await this.testDiscord(testThreat);
    } else {
      console.log('⚠️  Discord webhook not configured');
    }

    // Test Slack
    if (this.config.slack) {
      console.log('📧 Testing Slack webhook...');
      await this.testSlack(testThreat);
    } else {
      console.log('⚠️  Slack webhook not configured');
    }

    // Test Telegram
    if (this.config.telegram) {
      console.log('📧 Testing Telegram bot...');
      await this.testTelegram(testThreat);
    } else {
      console.log('⚠️  Telegram bot not configured');
    }

    console.log('\n✅ Webhook testing completed!');
  }

  async testDiscord(threat: TestThreat): Promise<void> {
    const embed = {
      title: `🧪 TEST: ${threat.type.toUpperCase().replace('_', ' ')} DETECTED`,
      color: 0xFF0000,
      fields: [
        { name: 'Severity', value: threat.severity.toUpperCase(), inline: true },
        { name: 'Confidence', value: `${(threat.confidence * 100).toFixed(1)}%`, inline: true },
        { name: 'Contract', value: `\`${threat.contractAddress}\``, inline: false },
        { name: 'Transaction', value: `\`${threat.transactionHash}\``, inline: false },
        { name: 'Test Status', value: '✅ Webhook functioning correctly', inline: false }
      ],
      footer: { text: 'Sei Threat Detection Agent - TEST MODE' },
      timestamp: new Date().toISOString()
    };

    try {
      const response = await fetch(this.config.discord!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ embeds: [embed] })
      });

      if (response.ok) {
        console.log('✅ Discord webhook test successful');
      } else {
        console.log(`❌ Discord webhook test failed: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('❌ Discord webhook error:', error);
    }
  }

  async testSlack(threat: TestThreat): Promise<void> {
    const payload = {
      text: `🧪 *TEST: ${threat.type.toUpperCase().replace('_', ' ')} DETECTED*`,
      attachments: [{
        color: 'danger',
        fields: [
          { title: 'Severity', value: threat.severity.toUpperCase(), short: true },
          { title: 'Confidence', value: `${(threat.confidence * 100).toFixed(1)}%`, short: true },
          { title: 'Contract', value: threat.contractAddress, short: false },
          { title: 'Transaction', value: threat.transactionHash, short: false },
          { title: 'Test Status', value: '✅ Webhook functioning correctly', short: false }
        ],
        footer: 'Sei Threat Detection Agent - TEST MODE',
        ts: Math.floor(threat.timestamp / 1000)
      }]
    };

    try {
      const response = await fetch(this.config.slack!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        console.log('✅ Slack webhook test successful');
      } else {
        console.log(`❌ Slack webhook test failed: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('❌ Slack webhook error:', error);
    }
  }

  async testTelegram(threat: TestThreat): Promise<void> {
    const message = [
      `🧪 *TEST: ${threat.type.toUpperCase().replace('_', ' ')} DETECTED*`,
      ``,
      `*Severity:* ${threat.severity.toUpperCase()}`,
      `*Confidence:* ${(threat.confidence * 100).toFixed(1)}%`,
      `*Contract:* \`${threat.contractAddress}\``,
      `*Transaction:* \`${threat.transactionHash}\``,
      `*Test Status:* ✅ Webhook functioning correctly`,
      ``,
      `_Sei Threat Detection Agent - TEST MODE_`
    ].join('\n');

    const url = `https://api.telegram.org/bot${this.config.telegram!.botToken}/sendMessage`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: this.config.telegram!.chatId,
          text: message,
          parse_mode: 'Markdown'
        })
      });

      if (response.ok) {
        console.log('✅ Telegram bot test successful');
      } else {
        const errorData = await response.json();
        console.log(`❌ Telegram bot test failed:`, errorData);
      }
    } catch (error) {
      console.error('❌ Telegram bot error:', error);
    }
  }

  async validateConfiguration(): Promise<void> {
    console.log('🔧 Validating webhook configuration...\n');

    console.log('Discord Webhook:');
    if (this.config.discord) {
      console.log(`  ✅ Configured: ${this.config.discord.substring(0, 50)}...`);
      
      // Test webhook URL format
      if (this.config.discord.includes('discord.com/api/webhooks/')) {
        console.log('  ✅ URL format looks correct');
      } else {
        console.log('  ⚠️  URL format may be incorrect');
      }
    } else {
      console.log('  ❌ Not configured (DISCORD_WEBHOOK missing)');
    }

    console.log('\nSlack Webhook:');
    if (this.config.slack) {
      console.log(`  ✅ Configured: ${this.config.slack.substring(0, 50)}...`);
      
      if (this.config.slack.includes('hooks.slack.com/services/')) {
        console.log('  ✅ URL format looks correct');
      } else {
        console.log('  ⚠️  URL format may be incorrect');
      }
    } else {
      console.log('  ❌ Not configured (SLACK_WEBHOOK missing)');
    }

    console.log('\nTelegram Bot:');
    if (this.config.telegram) {
      console.log(`  ✅ Bot Token: ${this.config.telegram.botToken.substring(0, 20)}...`);
      console.log(`  ✅ Chat ID: ${this.config.telegram.chatId}`);
      
      // Test bot token format
      if (this.config.telegram.botToken.includes(':')) {
        console.log('  ✅ Bot token format looks correct');
      } else {
        console.log('  ⚠️  Bot token format may be incorrect');
      }
    } else {
      console.log('  ❌ Not configured (TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing)');
    }

    console.log('\n📋 Configuration validation completed!');
  }

  async performFullTest(): Promise<void> {
    console.log('🚀 Starting comprehensive webhook test suite...\n');
    
    await this.validateConfiguration();
    console.log('\n' + '='.repeat(50) + '\n');
    await this.testAllWebhooks();
    
    // Test different severity levels
    console.log('\n🎭 Testing different severity levels...');
    
    const severityTests = [
      { severity: 'low', type: 'suspicious_pattern' },
      { severity: 'medium', type: 'suspicious_pattern' },
      { severity: 'high', type: 'exploit' },
      { severity: 'critical', type: 'flash_loan_attack' }
    ];

    for (const test of severityTests) {
      console.log(`\n📊 Testing ${test.severity} severity ${test.type}...`);
      
      const testThreat: TestThreat = {
        type: test.type,
        severity: test.severity,
        contractAddress: '0x' + Math.random().toString(16).substr(2, 40),
        transactionHash: '0x' + Math.random().toString(16).substr(2, 64),
        timestamp: Date.now(),
        confidence: Math.random() * 0.3 + 0.7, // 0.7 to 1.0
        details: {
          testCase: `${test.severity}_${test.type}`,
          gasPrice: Math.floor(Math.random() * 200000000000) + 50000000000,
          value: (Math.random() * 100000000000000000000).toString()
        }
      };

      // Only test Discord for brevity (you can extend this)
      if (this.config.discord) {
        await new Promise(resolve => setTimeout(resolve, 1000)); // Rate limiting
        await this.testDiscord(testThreat);
      }
    }

    console.log('\n🎉 Full webhook testing completed!');
    console.log('\n💡 Next steps:');
    console.log('   1. Check your Discord/Slack/Telegram channels for test messages');
    console.log('   2. If tests failed, verify your webhook URLs and tokens');
    console.log('   3. Run the main detector with: npm run dev');
  }
}

async function main() {
  const tester = new WebhookTester();
  
  // Check if any webhooks are configured
  const hasWebhooks = process.env.DISCORD_WEBHOOK || 
                     process.env.SLACK_WEBHOOK || 
                     (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID);

  if (!hasWebhooks) {
    console.log('❌ No webhooks configured in .env file');
    console.log('Please configure at least one of:');
    console.log('  - DISCORD_WEBHOOK');
    console.log('  - SLACK_WEBHOOK');
    console.log('  - TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID');
    process.exit(1);
  }

  try {
    await tester.performFullTest();
  } catch (error) {
    console.error('❌ Test suite failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

export { WebhookTester };