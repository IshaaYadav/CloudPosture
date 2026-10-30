import axios, { AxiosInstance } from 'axios';
import type {
  AWSStatus,
  EC2Instance,
  S3Bucket,
  CheckResult,
  ScanReport,
  ScanHistoryItem,
  ScanSummary,
  StorageVerification,
  HealthResponse,
} from '../types';

const BASE_URL = (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000';

const apiClient: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

function extractErrorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (detail && typeof detail === 'object' && 'msg' in detail) return (detail as any).msg;
    if (err.response?.data?.message) return err.response.data.message;
    if (err.message) return err.message;
  }
  if (err instanceof Error) return err.message;
  return 'An unexpected error occurred';
}

const api = {
  async getHealth(): Promise<HealthResponse> {
    try {
      const { data } = await apiClient.get<HealthResponse>('/health');
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async getAWSStatus(): Promise<AWSStatus> {
    try {
      const { data } = await apiClient.get<AWSStatus>('/aws/status');
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async verifyAWS(): Promise<AWSStatus> {
    try {
      const { data } = await apiClient.post<AWSStatus>('/aws/verify');
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async verifyStorage(): Promise<StorageVerification> {
    try {
      const { data } = await apiClient.post<StorageVerification>('/storage/verify');
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async runScan(): Promise<ScanReport> {
    try {
      const { data } = await apiClient.post<ScanReport>('/scan', null, {
        timeout: 120000,
      });
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async getInstances(): Promise<EC2Instance[]> {
    try {
      const { data } = await apiClient.get<EC2Instance[]>('/inventory/instances');
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async getBuckets(): Promise<S3Bucket[]> {
    try {
      const { data } = await apiClient.get<S3Bucket[]>('/inventory/buckets');
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async getCISResults(): Promise<CheckResult[]> {
    try {
      const { data } = await apiClient.get<CheckResult[]>('/cis/results');
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async getCISResult(checkId: string): Promise<CheckResult> {
    try {
      const { data } = await apiClient.get<CheckResult>(`/cis/results/${checkId}`);
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async getLatestScan(): Promise<ScanReport> {
    try {
      const { data } = await apiClient.get<ScanReport>('/scan/latest');
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async getScanHistory(): Promise<ScanHistoryItem[]> {
    try {
      const { data } = await apiClient.get<ScanHistoryItem[]>('/scan/history');
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async getScanById(scanId: string): Promise<ScanReport> {
    try {
      const { data } = await apiClient.get<ScanReport>(`/scan/${scanId}`);
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },

  async getSummary(): Promise<ScanSummary> {
    try {
      const { data } = await apiClient.get<ScanSummary>('/scan/summary');
      return data;
    } catch (err) {
      throw new Error(extractErrorMessage(err));
    }
  },
};

export default api;
