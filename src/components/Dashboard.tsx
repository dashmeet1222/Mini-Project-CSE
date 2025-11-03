import React from 'react';
import { Shield, Activity, AlertTriangle, TrendingUp, Database, Zap } from 'lucide-react';

interface DashboardProps {
  systemStatus: {
    networkCapture: boolean;
    featureExtraction: boolean;
    mlInference: boolean;
    alerting: boolean;
  };
  threats: any[];
  alerts: any[];
}

const Dashboard: React.FC<DashboardProps> = ({ systemStatus, threats, alerts }) => {
  const criticalAlerts = alerts.filter(alert => alert.severity === 'Critical').length;
  const highAlerts = alerts.filter(alert => alert.severity === 'High').length;
  
  const systemHealth = Object.values(systemStatus).every(status => status) ? 100 : 75;

  return (
    <div className="space-y-6">
      {/* System Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">System Health</p>
              <p className="text-2xl font-bold text-emerald-400">{systemHealth}%</p>
            </div>
            <Activity className="h-8 w-8 text-emerald-400" />
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
              <p className="text-slate-400 text-sm">Active Threats</p>
              <p className="text-2xl font-bold text-red-400">{threats.length}</p>
            </div>
            <AlertTriangle className="h-8 w-8 text-red-400" />
          </div>
          <p className="text-xs text-slate-500 mt-2">Last updated: just now</p>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Critical Alerts</p>
              <p className="text-2xl font-bold text-orange-400">{criticalAlerts}</p>
            </div>
            <Shield className="h-8 w-8 text-orange-400" />
          </div>
          <p className="text-xs text-slate-500 mt-2">+{highAlerts} high priority</p>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Detection Rate</p>
              <p className="text-2xl font-bold text-blue-400">94.7%</p>
            </div>
            <TrendingUp className="h-8 w-8 text-blue-400" />
          </div>
          <p className="text-xs text-emerald-400 mt-2">↑ 2.3% from last hour</p>
        </div>
      </div>

      {/* System Components Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">System Components</h3>
          <div className="space-y-4">
            {[
              { name: 'Network Capture', status: systemStatus.networkCapture, icon: Database },
              { name: 'Feature Extraction', status: systemStatus.featureExtraction, icon: Activity },
              { name: 'ML Detection Engine', status: true, icon: Zap },
              { name: 'Alerting System', status: systemStatus.alerting, icon: Shield },
            ].map((component) => {
              const Icon = component.icon;
              return (
                <div key={component.name} className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <Icon className="h-5 w-5 text-slate-400" />
                    <span className="text-slate-300">{component.name}</span>
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
          <h3 className="text-lg font-semibold mb-4 text-white">Recent Threats</h3>
          <div className="space-y-3">
            {threats.slice(0, 5).map((threat) => (
              <div key={threat.id} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                <div>
                  <p className="text-sm font-medium text-white">{threat.type}</p>
                  <p className="text-xs text-slate-400">{threat.source} • {threat.timestamp}</p>
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
          </div>
        </div>
      </div>

      {/* Real-time Metrics */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Performance Metrics</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <p className="text-2xl font-bold text-emerald-400">1,247</p>
            <p className="text-sm text-slate-400">Packets/sec</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-blue-400">23ms</p>
            <p className="text-sm text-slate-400">Avg Response Time</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-purple-400">847MB</p>
            <p className="text-sm text-slate-400">Memory Usage</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;