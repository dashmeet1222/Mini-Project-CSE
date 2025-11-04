import React, { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, TrendingUp, Database, Zap, Globe, Network } from 'lucide-react';

interface NetworkDashboardProps {
  systemStatus: {
    networkCapture: boolean;
    featureExtraction: boolean;
    mlInference: boolean;
    alerting: boolean;
  };
  threats: any[];
  alerts: any[];
}

const NetworkDashboard: React.FC<NetworkDashboardProps> = ({ systemStatus, threats, alerts }) => {
  const [networkStats, setNetworkStats] = useState({
    totalHosts: 0,
    activeFlows: 0,
    networkSegments: 0,
    monitoredInterfaces: 0,
  });

  const [networkMetrics, setNetworkMetrics] = useState({
    packetsPerSecond: 0,
    bytesPerSecond: 0,
    flowsPerSecond: 0,
    networkUtilization: 0,
  });

  useEffect(() => {
    const interval = setInterval(() => {
      setNetworkStats({
        totalHosts: Math.floor(Math.random() * 50) + 150,
        activeFlows: Math.floor(Math.random() * 500) + 1000,
        networkSegments: Math.floor(Math.random() * 5) + 8,
        monitoredInterfaces: Math.floor(Math.random() * 2) + 4,
      });

      setNetworkMetrics({
        packetsPerSecond: Math.floor(Math.random() * 2000) + 3000,
        bytesPerSecond: Math.floor(Math.random() * 50) + 100,
        flowsPerSecond: Math.floor(Math.random() * 100) + 200,
        networkUtilization: Math.floor(Math.random() * 30) + 60,
      });
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  const criticalAlerts = alerts.filter(alert => alert.severity === 'Critical').length;
  const highAlerts = alerts.filter(alert => alert.severity === 'High').length;
  
  const systemHealth = Object.values(systemStatus).every(status => status) ? 100 : 75;

  return (
    <div className="space-y-6">
      {/* NIDS Header */}
      <div className="bg-gradient-to-r from-slate-800 to-slate-700 p-6 rounded-xl border border-slate-600">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">Network Intrusion Detection System</h1>
            <p className="text-slate-300">Real-time network monitoring and threat detection across your infrastructure</p>
          </div>
          <div className="flex items-center space-x-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-emerald-400">{networkStats.totalHosts}</div>
              <div className="text-sm text-slate-400">Network Hosts</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-400">{networkStats.networkSegments}</div>
              <div className="text-sm text-slate-400">Network Segments</div>
            </div>
          </div>
        </div>
      </div>

      {/* Network System Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Network Health</p>
              <p className="text-2xl font-bold text-emerald-400">{systemHealth}%</p>
            </div>
            <Network className="h-8 w-8 text-emerald-400" />
          </div>
          <div className="mt-4 bg-slate-700 rounded-full h-2">
            <div 
              className="bg-emerald-400 h-2 rounded-full transition-all duration-500"
              style={{ width: `${systemHealth}%` }}
            />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Network Threats</p>
              <p className="text-2xl font-bold text-red-400">{threats.length}</p>
            </div>
            <AlertTriangle className="h-8 w-8 text-red-400" />
          </div>
          <p className="text-xs text-slate-500 mt-2">Across {networkStats.networkSegments} segments</p>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Active Flows</p>
              <p className="text-2xl font-bold text-blue-400">{networkStats.activeFlows.toLocaleString()}</p>
            </div>
            <Activity className="h-8 w-8 text-blue-400" />
          </div>
          <p className="text-xs text-emerald-400 mt-2">↑ {networkMetrics.flowsPerSecond}/sec</p>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Network Utilization</p>
              <p className="text-2xl font-bold text-purple-400">{networkMetrics.networkUtilization}%</p>
            </div>
            <TrendingUp className="h-8 w-8 text-purple-400" />
          </div>
          <p className="text-xs text-slate-500 mt-2">{networkMetrics.bytesPerSecond} MB/s throughput</p>
        </div>
      </div>

      {/* Network Components Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Network Monitoring Components</h3>
          <div className="space-y-4">
            {[
              { name: 'Deep Packet Inspection', status: systemStatus.networkCapture, icon: Database, description: 'Layer 2-7 analysis' },
              { name: 'Network Flow Analysis', status: systemStatus.featureExtraction, icon: Activity, description: 'Bidirectional flow tracking' },
              { name: 'Network ML Engine', status: true, icon: Zap, description: 'Network behavior analysis' },
              { name: 'Network Alerting', status: systemStatus.alerting, icon: Shield, description: 'Multi-channel notifications' },
            ].map((component) => {
              const Icon = component.icon;
              return (
                <div key={component.name} className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <Icon className="h-5 w-5 text-slate-400" />
                    <div>
                      <span className="text-slate-300 font-medium">{component.name}</span>
                      <p className="text-xs text-slate-500">{component.description}</p>
                    </div>
                  </div>
                  <div className={`flex items-center space-x-2 ${component.status ? 'text-emerald-400' : 'text-red-400'}`}>
                    <div className={`h-2 w-2 rounded-full ${component.status ? 'bg-emerald-400' : 'bg-red-400'}`} />
                    <span className="text-sm">{component.status ? 'Active' : 'Inactive'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Network Threat Intelligence</h3>
          <div className="space-y-3">
            {threats.slice(0, 5).map((threat, index) => (
              <div key={threat.id || index} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                <div>
                  <p className="text-sm font-medium text-white">{threat.type || threat.threat_type}</p>
                  <p className="text-xs text-slate-400">
                    {threat.source || threat.src_ip} → Network Segment
                  </p>
                </div>
                <div className={`px-2 py-1 rounded text-xs font-medium ${
                  threat.severity === 'Critical' ? 'bg-red-600 text-white' :
                  threat.severity === 'High' ? 'bg-orange-600 text-white' :
                  threat.severity === 'Medium' ? 'bg-yellow-600 text-black' :
                  'bg-green-600 text-white'
                }`}>
                  {threat.severity}
                </div>
              </div>
            ))}
            {threats.length === 0 && (
              <div className="text-center py-4">
                <Shield className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
                <p className="text-slate-400 text-sm">Network is secure</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Network Performance Metrics */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Real-time Network Performance</h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="text-center">
            <div className="flex items-center justify-center mb-2">
              <Activity className="h-6 w-6 text-emerald-400 mr-2" />
              <span className="text-slate-400">Packets/sec</span>
            </div>
            <p className="text-2xl font-bold text-emerald-400">{networkMetrics.packetsPerSecond.toLocaleString()}</p>
            <div className="mt-2 bg-slate-700 rounded-full h-1">
              <div 
                className="bg-emerald-400 h-1 rounded-full transition-all duration-500"
                style={{ width: `${Math.min(networkMetrics.packetsPerSecond / 50, 100)}%` }}
              />
            </div>
          </div>

          <div className="text-center">
            <div className="flex items-center justify-center mb-2">
              <Database className="h-6 w-6 text-blue-400 mr-2" />
              <span className="text-slate-400">Network Flows</span>
            </div>
            <p className="text-2xl font-bold text-blue-400">{networkMetrics.flowsPerSecond}</p>
            <div className="mt-2 bg-slate-700 rounded-full h-1">
              <div 
                className="bg-blue-400 h-1 rounded-full transition-all duration-500"
                style={{ width: `${Math.min(networkMetrics.flowsPerSecond / 3, 100)}%` }}
              />
            </div>
          </div>

          <div className="text-center">
            <div className="flex items-center justify-center mb-2">
              <Globe className="h-6 w-6 text-purple-400 mr-2" />
              <span className="text-slate-400">Throughput</span>
            </div>
            <p className="text-2xl font-bold text-purple-400">{networkMetrics.bytesPerSecond} MB/s</p>
            <div className="mt-2 bg-slate-700 rounded-full h-1">
              <div 
                className="bg-purple-400 h-1 rounded-full transition-all duration-500"
                style={{ width: `${Math.min(networkMetrics.bytesPerSecond, 100)}%` }}
              />
            </div>
          </div>

          <div className="text-center">
            <div className="flex items-center justify-center mb-2">
              <Zap className="h-6 w-6 text-orange-400 mr-2" />
              <span className="text-slate-400">ML Inference</span>
            </div>
            <p className="text-2xl font-bold text-orange-400">12ms</p>
            <p className="text-xs text-slate-500 mt-1">Average latency</p>
          </div>
        </div>
      </div>

      {/* Network Topology Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Network Segments</h3>
          <div className="space-y-3">
            {[
              { name: 'DMZ', hosts: 12, status: 'secure', utilization: 45 },
              { name: 'Internal LAN', hosts: 89, status: 'monitoring', utilization: 67 },
              { name: 'Server Farm', hosts: 24, status: 'secure', utilization: 78 },
              { name: 'Guest Network', hosts: 15, status: 'alert', utilization: 23 },
            ].map((segment) => (
              <div key={segment.name} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                <div>
                  <p className="font-medium text-white">{segment.name}</p>
                  <p className="text-sm text-slate-400">{segment.hosts} hosts</p>
                </div>
                <div className="text-right">
                  <div className={`px-2 py-1 rounded text-xs font-medium ${
                    segment.status === 'secure' ? 'bg-emerald-600 text-white' :
                    segment.status === 'monitoring' ? 'bg-blue-600 text-white' :
                    'bg-red-600 text-white'
                  }`}>
                    {segment.status}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{segment.utilization}% util</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Network Protocols</h3>
          <div className="space-y-3">
            {[
              { protocol: 'TCP', percentage: 67, packets: '2.1M' },
              { protocol: 'UDP', percentage: 23, packets: '720K' },
              { protocol: 'ICMP', percentage: 6, packets: '180K' },
              { protocol: 'Other', percentage: 4, packets: '120K' },
            ].map((proto) => (
              <div key={proto.protocol} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{
                      backgroundColor: proto.protocol === 'TCP' ? '#10b981' :
                                     proto.protocol === 'UDP' ? '#3b82f6' :
                                     proto.protocol === 'ICMP' ? '#8b5cf6' : '#6b7280'
                    }}
                  />
                  <span className="text-slate-300">{proto.protocol}</span>
                </div>
                <div className="text-right">
                  <span className="text-white font-medium">{proto.percentage}%</span>
                  <p className="text-xs text-slate-400">{proto.packets}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Network Services</h3>
          <div className="space-y-3">
            {[
              { service: 'HTTPS', port: 443, connections: 1247 },
              { service: 'HTTP', port: 80, connections: 892 },
              { service: 'DNS', port: 53, connections: 456 },
              { service: 'SSH', port: 22, connections: 89 },
            ].map((service) => (
              <div key={service.service} className="flex items-center justify-between p-2 bg-slate-700 rounded">
                <div>
                  <p className="text-sm font-medium text-white">{service.service}</p>
                  <p className="text-xs text-slate-400">Port {service.port}</p>
                </div>
                <div className="text-right">
                  <p className="text-sm text-emerald-400">{service.connections}</p>
                  <p className="text-xs text-slate-400">connections</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkDashboard;