/**
 * API service for communicating with Python backend
 */

const API_BASE_URL = 'http://localhost:5000/api';

export interface ApiResponse<T> {
  data?: T;
  error?: string;
  status: 'success' | 'error';
}

export interface SystemStatus {
  monitoring_active: boolean;
  ml_models_trained: boolean;
  uptime: number;
  timestamp: string;
}

export interface NetworkPacket {
  timestamp: string;
  src_ip: string;
  dest_ip: string;
  src_port?: number;
  dest_port?: number;
  protocol: string;
  size: number;
  flags?: number;
}

export interface ThreatDetection {
  id?: string;
  threat_type: string;
  severity: string;
  confidence: number;
  src_ip: string;
  dest_ip?: string;
  timestamp: string;
  ml_prediction?: string;
  anomaly_detected?: boolean;
}

export interface TrafficStats {
  total_packets: number;
  total_bytes: number;
  [protocol: string]: number;
}

export interface FlowFeature {
  flow_id: string;
  src_ip: string;
  dest_ip: string;
  src_port: number;
  dest_port: number;
  protocol: string;
  duration: number;
  packet_count: number;
  total_bytes: number;
  packet_rate: number;
  byte_rate: number;
}

class ApiService {
  private async request<T>(endpoint: string, options?: RequestInit): Promise<ApiResponse<T>> {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          ...options?.headers,
        },
        timeout: 5000, // 5 second timeout
        ...options,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return { data, status: 'success' };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      // Check if it's a network error (backend not running)
      if (errorMessage.includes('Failed to fetch') || errorMessage.includes('fetch')) {
        console.warn(`Backend server not available for ${endpoint}. Using fallback data.`);
        return this.getFallbackData<T>(endpoint);
      }
      
      console.error(`API request failed for ${endpoint}:`, error);
      return { 
        error: errorMessage,
        status: 'error' 
      };
    }
  }

  private getFallbackData<T>(endpoint: string): ApiResponse<T> {
    // Provide fallback data when backend is not available
    switch (endpoint) {
      case '/status':
        return {
          data: {
            monitoring_active: false,
            ml_models_trained: false,
            uptime: 0,
            timestamp: new Date().toISOString()
          } as T,
          status: 'success'
        };
      
      case '/threats':
        return {
          data: {
            threats: [],
            total_count: 0
          } as T,
          status: 'success'
        };
      
      default:
        if (endpoint.startsWith('/packets')) {
          return {
            data: {
              packets: [],
              total_count: 0
            } as T,
            status: 'success'
          };
        }
        
        return {
          error: 'Backend server not available',
          status: 'error'
        };
    }
  }

  // System control endpoints
  async getSystemStatus(): Promise<ApiResponse<SystemStatus>> {
    return this.request<SystemStatus>('/status');
  }

  async startMonitoring(): Promise<ApiResponse<{ message: string }>> {
    return this.request('/monitoring/start', { method: 'POST' });
  }

  async stopMonitoring(): Promise<ApiResponse<{ message: string }>> {
    return this.request('/monitoring/stop', { method: 'POST' });
  }

  // Data retrieval endpoints
  async getPackets(count = 50): Promise<ApiResponse<{ packets: NetworkPacket[]; total_count: number }>> {
    return this.request(`/packets?count=${count}`);
  }

  async getThreats(): Promise<ApiResponse<{ threats: ThreatDetection[]; total_count: number }>> {
    return this.request('/threats');
  }

  async getStatistics(): Promise<ApiResponse<{ traffic_stats: TrafficStats; system_stats: any }>> {
    return this.request('/statistics');
  }

  async getFlowAnalysis(): Promise<ApiResponse<{ flows: FlowFeature[]; total_count: number }>> {
    return this.request('/analysis/flows');
  }

  // ML endpoints
  async trainModels(trainingData?: any): Promise<ApiResponse<{ model_info: any }>> {
    return this.request('/ml/train', {
      method: 'POST',
      body: trainingData ? JSON.stringify(trainingData) : undefined,
    });
  }

  async predictThreats(flowData?: FlowFeature[]): Promise<ApiResponse<{ predictions: ThreatDetection[] }>> {
    return this.request('/ml/predict', {
      method: 'POST',
      body: flowData ? JSON.stringify(flowData) : undefined,
    });
  }

  async getModelInfo(): Promise<ApiResponse<any>> {
    return this.request('/ml/models');
  }

  // Export endpoints
  async exportPackets(): Promise<ApiResponse<{ filename: string }>> {
    return this.request('/export/packets');
  }

  async exportAnalysis(): Promise<ApiResponse<{ filename: string }>> {
    return this.request('/export/analysis');
  }

  // Health check
  async healthCheck(): Promise<ApiResponse<{ status: string; version: string }>> {
    return this.request('/health');
  }
}

export const apiService = new ApiService();