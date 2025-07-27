// services/alerts.ts
import axios from 'axios';
import { WebhookClient } from 'discord.js';
import { DetectorConfig, ThreatAlert } from '../types/index';

export class SocialAlertSystem {
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