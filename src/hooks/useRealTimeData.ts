/**
 * Custom hook for real-time data fetching from Python backend
 */

import { useState, useEffect, useCallback } from 'react';
import { apiService, NetworkPacket, ThreatDetection, SystemStatus } from '../services/api';

export interface RealTimeData {
  packets: NetworkPacket[];
  threats: ThreatDetection[];
  systemStatus: SystemStatus | null;
  isConnected: boolean;
  error: string | null;
}

export const useRealTimeData = (refreshInterval = 2000) => {
  const [data, setData] = useState<RealTimeData>({
    packets: [],
    threats: [],
    systemStatus: null,
    isConnected: false,
    error: null,
  });

  const [isLoading, setIsLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      // Fetch all data concurrently
      const [statusResponse, packetsResponse, threatsResponse] = await Promise.allSettled([
        apiService.getSystemStatus(),
        apiService.getPackets(100),
        apiService.getThreats(),
      ]);

      const newData: Partial<RealTimeData> = {};

      // Process system status
      if (statusResponse.status === 'fulfilled' && statusResponse.value.status === 'success' && statusResponse.value.data) {
        newData.systemStatus = statusResponse.value.data;
        newData.isConnected = true;
      } else {
        newData.isConnected = false;
      }

      // Process packets
      if (packetsResponse.status === 'fulfilled' && packetsResponse.value.status === 'success' && packetsResponse.value.data) {
        newData.packets = packetsResponse.value.data.packets;
      } else {
        newData.packets = [];
      }

      // Process threats
      if (threatsResponse.status === 'fulfilled' && threatsResponse.value.status === 'success' && threatsResponse.value.data) {
        newData.threats = threatsResponse.value.data.threats;
      } else {
        newData.threats = [];
      }

      setData(prevData => ({
        ...prevData,
        ...newData,
        error: newData.isConnected ? null : 'Backend server not available - using demo mode',
      }));

      setIsLoading(false);
    } catch (error) {
      console.error('Error fetching real-time data:', error);
      setData(prevData => ({
        ...prevData,
        packets: [],
        threats: [],
        systemStatus: null,
        isConnected: false,
        error: 'Backend server not available - using demo mode',
      }));
      setIsLoading(false);
    }
  }, []);

  // Initial data fetch
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Set up polling interval
  useEffect(() => {
    const interval = setInterval(fetchData, refreshInterval);
    return () => clearInterval(interval);
  }, [fetchData, refreshInterval]);

  const startMonitoring = useCallback(async () => {
    const response = await apiService.startMonitoring();
    if (response.status === 'success') {
      // Refresh data immediately
      fetchData();
    }
    return response;
  }, [fetchData]);

  const stopMonitoring = useCallback(async () => {
    const response = await apiService.stopMonitoring();
    if (response.status === 'success') {
      // Refresh data immediately
      fetchData();
    }
    return response;
  }, [fetchData]);

  const trainModels = useCallback(async () => {
    const response = await apiService.trainModels();
    if (response.status === 'success') {
      // Refresh data immediately
      fetchData();
    }
    return response;
  }, [fetchData]);

  return {
    ...data,
    isLoading,
    refresh: fetchData,
    startMonitoring,
    stopMonitoring,
    trainModels,
  };
};

export default useRealTimeData;