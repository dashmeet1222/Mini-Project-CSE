import React, { useState, useEffect } from 'react';
import useRealTimeData from './hooks/useRealTimeData';
import Dashboard from './components/Dashboard';
import NetworkTraffic from './components/NetworkTraffic';
import PacketCapture from './components/PacketCapture';
import FeatureExtraction from './components/FeatureExtraction';
import MLTraining from './components/MLTraining';
import InferenceEngine from './components/InferenceEngine';
import AlertingSystem from './components/AlertingSystem';
import ResponseSystem from './components/ResponseSystem';
import { Shield, Activity, Brain, Bell, Zap, Database, Settings } from 'lucide-react';

const navigationItems = [
  { id: 'dashboard', label: 'Dashboard', icon: Activity },
  { id: 'network', label: 'Network Traffic', icon: Activity },
  { id: 'capture', label: 'Packet Capture', icon: Database },
  { id: 'features', label: 'Feature Extraction', icon: Settings },
  { id: 'inference', label: 'Inference Engine', icon: Zap },
  { id: 'alerts', label: 'Alerts', icon: Bell },
  { id: 'response', label: 'Response', icon: Shield },
];

function App() {
  const [activeSection, setActiveSection] = useState('dashboard');
  
  // Use real-time data hook
  const {
    packets,
    threats,
    systemStatus,
    isConnected,
    error,
    isLoading,
    startMonitoring,
    stopMonitoring,
    trainModels
  } = useRealTimeData();

  // Convert threats to alerts format
  const [alerts, setAlerts] = useState<any[]>([]);
  
  useEffect(() => {
    const newAlerts = threats.map(threat => ({
      id: threat.id || Date.now(),
      type: threat.threat_type,
      severity: threat.severity,
      source: threat.src_ip,
      timestamp: new Date(threat.timestamp).toLocaleTimeString(),
      confidence: threat.confidence,
      status: 'Active',
      acknowledged: false,
    }));
    setAlerts(newAlerts);
  }, [threats]);

  // Convert system status
  const convertedSystemStatus = {
    networkCapture: systemStatus?.monitoring_active || false,
    featureExtraction: isConnected,
    mlInference: systemStatus?.ml_models_trained || false,
    alerting: isConnected,
  };

  const renderActiveSection = () => {
    switch (activeSection) {
      case 'dashboard':
        return <Dashboard systemStatus={convertedSystemStatus} threats={threats} alerts={alerts} />;
      case 'network':
        return <NetworkTraffic packets={packets} />;
      case 'capture':
        return <PacketCapture isMonitoring={systemStatus?.monitoring_active} onStartStop={systemStatus?.monitoring_active ? stopMonitoring : startMonitoring} />;
      case 'features':
        return <FeatureExtraction packets={packets} />;
      case 'inference':
        return <InferenceEngine threats={threats} />;
      case 'alerts':
        return <AlertingSystem alerts={alerts} setAlerts={setAlerts} />;
      case 'response':
        return <ResponseSystem threats={threats} />;
      default:
        return <Dashboard systemStatus={convertedSystemStatus} threats={threats} alerts={alerts} />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-emerald-400" />
            <h1 className="text-xl font-bold text-white">SecureNet IDS</h1>
            <span className="text-sm text-slate-400">v2.1.0</span>
          </div>
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <div className={`h-2 w-2 rounded-full ${isConnected ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`}></div>
              <span className="text-sm text-slate-300">
                {isConnected ? 'System Active' : 'Disconnected'}
              </span>
            </div>
            {error && (
              <div className="text-sm text-red-400">
                Error: {error}
              </div>
            )}
            <div className="text-sm text-slate-400">
              {new Date().toLocaleTimeString()}
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <nav className="w-64 bg-slate-800 border-r border-slate-700 min-h-screen p-4">
          <div className="space-y-2">
            {navigationItems.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveSection(item.id)}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                    activeSection === item.id
                      ? 'bg-emerald-600 text-white shadow-lg'
                      : 'text-slate-300 hover:bg-slate-700 hover:text-white'
                  }`}
                >
                  <Icon className="h-5 w-5" />
                  <span className="font-medium">{item.label}</span>
                </button>
              );
            })}
          </div>
        </nav>

        {/* Main Content */}
        <main className="flex-1 p-6">
          {renderActiveSection()}
        </main>
      </div>
    </div>
  );
}

export default App;