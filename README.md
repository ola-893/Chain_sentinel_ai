# Enhanced Sei Threat Detection Agent

A sophisticated, real-time blockchain threat detection system for the Sei network that monitors live transactions and identifies potential security risks including rug pulls, flash loan attacks, MEV activities, and other malicious patterns.

## 🚀 Features

- **Real-time Blockchain Monitoring**: Connects directly to Sei EVM RPC for live transaction analysis
- **Multi-layered Threat Detection**: Local pattern recognition + optional Hive Intelligence API integration
- **Social Alert System**: Instant notifications via Discord, Slack, and Telegram
- **Automated Mitigation**: Configurable auto-response to critical threats
- **Comprehensive Analytics**: Real-time statistics and threat history tracking
- **Modular Architecture**: Clean separation of concerns for easy maintenance and extension

## 📁 Project Structure

```
sei-threat-detector/
├── src/
│   ├── types/
│   │   └── index.ts              # Type definitions
│   ├── config/
│   │   └── validator.ts          # Environment validation
│   ├── services/
│   │   ├── blockchain.ts         # Sei blockchain interaction
│   │   ├── alerts.ts            # Social alert system
│   │   └── hive-intelligence.ts  # Hive Intelligence API
│   ├── detectors/
│   │   ├── local-threat-detector.ts  # Local pattern detection
│   │   └── threat-processor.ts       # Threat analysis coordinator
│   ├── core/
│   │   └── enhanced-sei-detector.ts  # Main detector class
│   ├── utils/
│   │   └── test.ts           # Testing utilities
│   └── index.ts                 # Main entry point
├── package.json
├── tsconfig.json
└── README.md
```

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd sei-threat-detector
   ```

2. **Install dependencies**
   ```bash
   npm install
   # If you get module errors, also install:
   npm install ts-node typescript @types/node
   ```

3. **Create environment configuration**
   ```bash
   npm run example-env  # Shows example .env format
   cp .env.example .env  # Create your .env file
   ```

4. **Configure your .env file**
   ```env
   # Required
   PRIVATE_KEY=your_private_key_here

   # Sei Configuration
   SEI_RPC_URL=https://evm-rpc.sei-apis.com

   # Alert Configuration
   DISCORD_WEBHOOK=https://discord.com/api/webhooks/your_webhook_here

   # Optional: Hive Intelligence
   HIVE_ENABLED=false
   HIVE_API_KEY=your_hive_api_key_here
   ```

## 🚀 Usage

### Start the Threat Detector
```bash
npm run dev
```

### Run System Tests
```bash
npm run test
```

### Show Help
```bash
npm run help
```

### Build for Production
```bash
npm run build
npm start
```

## 🎯 Threat Detection Capabilities

### Local Detection Patterns
- **Gas Anomaly Detection**: Identifies unusually high gas prices indicating MEV activity
- **Large Value Transfers**: Monitors for significant token movements
- **MEV Activity Recognition**: Detects front-running and sandwich attacks
- **Suspicious Contract Patterns**: Identifies potentially malicious contract deployments
- **High-Frequency Interaction Analysis**: Monitors for unusual contract interaction patterns

### Hive Intelligence Integration (Optional)
- **Rug Pull Detection**: AI-powered analysis of exit scam indicators
- **Flash Loan Exploit Identification**: Detection of complex arbitrage attacks
- **MEV Strategy Recognition**: Advanced MEV pattern identification
- **Contract Risk Assessment**: Comprehensive smart contract security analysis

## 📱 Alert Systems

### Discord Integration
- Rich embed alerts with color-coded severity levels
- Detailed threat information and transaction links
- Real-time threat status updates

### Slack Integration
- Formatted alert messages with severity indicators
- Team collaboration features for threat response

### Telegram Integration
- Instant mobile notifications
- Markdown-formatted threat details

## 🛡️ Automated Mitigation

When enabled, the system can automatically respond to critical threats:

- **Contract Interaction Freeze**: Temporarily halt interactions with suspicious contracts
- **Emergency Pause Protocols**: Activate emergency pause mechanisms
- **Real-time Alert Escalation**: Immediate notification of critical threats

## 📊 Monitoring & Analytics

### Real-time Statistics
- Blocks processed per minute
- Transactions analyzed
- Threats detected and categorized
- System uptime and performance metrics

### Threat History
- Complete audit trail of all detected threats
- Confidence scoring and risk assessment
- Mitigation status tracking

## 🔧 Configuration Options

### Threat Thresholds
```env
LIQUIDITY_DRAIN_THRESHOLD=75
VOLUME_SPIKE_THRESHOLD=8
GAS_ANOMALY_THRESHOLD=120000000000
RUG_PULL_VELOCITY_THRESHOLD=50
FLASH_LOAN_MIN_VALUE=30000000000000000000
```

### Monitoring Settings
```env
POLLING_INTERVAL=200  # milliseconds
```

### Mitigation Controls
```env
MITIGATION_ENABLED=false
AUTO_FREEZE=false
EMERGENCY_PAUSE=false
MAX_MITIGATION_GAS=500000
```

## 🧪 Testing

The system includes comprehensive testing utilities:

```bash
# Test all system components
npm run test

# Test alert systems only
npm run dev -- --test-alerts

# Show configuration example
npm run example-env
```

## 🔌 API Integration

### Sei Blockchain
- **RPC Endpoint**: `https://evm-rpc.sei-apis.com`
- **Methods Used**: `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getTransactionByHash`
- **Real-time Block Processing**: Continuous monitoring of new blocks

### Hive Intelligence (Optional)
- **Natural Language Queries**: AI-powered threat analysis
- **Rate Limiting**: Built-in request throttling (18 requests/minute)
- **Retry Logic**: Automatic retry with exponential backoff

## 🚨 Security Considerations

- **Private Key Management**: Ensure secure storage of private keys
- **Webhook Security**: Use secure webhook URLs and validate payloads
- **Rate Limiting**: Built-in protection against API rate limits
- **Error Handling**: Comprehensive error handling and logging

## 📈 Performance

- **Low Latency**: Optimized for real-time threat detection
- **Scalable Architecture**: Modular design supports easy scaling
- **Resource Efficient**: Intelligent transaction filtering to optimize API usage
- **Dynamic Polling**: Adaptive polling intervals based on network activity

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:

1. Check the troubleshooting section below
2. Review the configuration examples
3. Open an issue on GitHub

### Troubleshooting

**Common Issues:**

1. **"PRIVATE_KEY is required"**
   - Ensure your `.env` file contains a valid private key

2. **Discord webhook failures**
   - Verify your Discord webhook URL is correct
   - Check Discord server permissions

3. **RPC connection issues**
   - Verify network connectivity to Sei RPC endpoint
   - Check for any firewall restrictions

4. **Hive Intelligence API errors**
   - Verify API key is correct
   - Check rate limiting status
   - Ensure sufficient API credits

**Performance Optimization:**

- Adjust `POLLING_INTERVAL` based on your monitoring needs
- Configure threat thresholds to reduce false positives
- Use Hive Intelligence selectively for high-value transactions only

---

Built with ❤️ for the Sei blockchain ecosystem
