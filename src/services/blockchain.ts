// services/blockchain.ts
import axios from 'axios';
import { DetectorConfig } from '../types/index';

export class SeiBlockchainService {
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