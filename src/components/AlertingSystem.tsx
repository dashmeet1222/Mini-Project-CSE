import React, { useState } from 'react';
import { Bell, Mail, MessageSquare, Monitor, Shield, Check, X, Clock } from 'lucide-react';

interface AlertingSystemProps {
  alerts: any[];
  setAlerts: React.Dispatch<React.SetStateAction<any[]>>;
}

const AlertingSystem: React.FC<AlertingSystemProps> = ({ alerts, setAlerts }) => {
  const [notificationChannels, setNotificationChannels] = useState({
    email: true,
    siem: true,
    slack: true,
    webhook: false,
  });

  const acknowledgeAlert = (alertId: number) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, acknowledged: true, status: 'Acknowledged' } : alert
    ));
  };

  const dismissAlert = (alertId: number) => {
    setAlerts(prev => prev.filter(alert => alert.id !== alertId));
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'border-red-400 bg-red-400/10';
      case 'High': return 'border-orange-400 bg-orange-400/10';
      case 'Medium': return 'border-yellow-400 bg-yellow-400/10';
      default: return 'border-green-400 bg-green-400/10';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'Active': return <Bell className="h-4 w-4 text-red-400" />;
      case 'Acknowledged': return <Check className="h-4 w-4 text-yellow-400" />;
      case 'Resolved': return <Shield className="h-4 w-4 text-green-400" />;
      default: return <Clock className="h-4 w-4 text-slate-400" />;
    }
  };

  const activeAlerts = alerts.filter(alert => alert.status === 'Active').length;
  const acknowledgedAlerts = alerts.filter(alert => alert.status === 'Acknowledged').length;
  const criticalAlerts = alerts.filter(alert => alert.severity === 'Critical').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Alerting System</h2>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className="h-2 w-2 bg-red-400 rounded-full animate-pulse" />
            <span className="text-sm text-slate-300">{activeAlerts} Active Alerts</span>
          </div>
        </div>
      </div>

      {/* Alert Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Total Alerts</p>
              <p className="text-2xl font-bold text-white">{alerts.length}</p>
            </div>
            <Bell className="h-8 w-8 text-emerald-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Active</p>
              <p className="text-2xl font-bold text-red-400">{activeAlerts}</p>
            </div>
            <Shield className="h-8 w-8 text-red-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Critical</p>
              <p className="text-2xl font-bold text-orange-400">{criticalAlerts}</p>
            </div>
            <X className="h-8 w-8 text-orange-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Acknowledged</p>
              <p className="text-2xl font-bold text-yellow-400">{acknowledgedAlerts}</p>
            </div>
            <Check className="h-8 w-8 text-yellow-400" />
          </div>
        </div>
      </div>

      {/* Notification Channels */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Notification Channels</h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="flex items-center justify-between p-4 bg-slate-700 rounded-lg">
            <div className="flex items-center space-x-3">
              <Mail className="h-6 w-6 text-blue-400" />
              <div>
                <p className="font-medium text-white">Email</p>
                <p className="text-sm text-slate-400">SMTP Alerts</p>
              </div>
            </div>
            <div className={`h-2 w-2 rounded-full ${notificationChannels.email ? 'bg-emerald-400' : 'bg-slate-500'}`} />
          </div>

          <div className="flex items-center justify-between p-4 bg-slate-700 rounded-lg">
            <div className="flex items-center space-x-3">
              <Monitor className="h-6 w-6 text-purple-400" />
              <div>
                <p className="font-medium text-white">SIEM</p>
                <p className="text-sm text-slate-400">Security Platform</p>
              </div>
            </div>
            <div className={`h-2 w-2 rounded-full ${notificationChannels.siem ? 'bg-emerald-400' : 'bg-slate-500'}`} />
          </div>

          <div className="flex items-center justify-between p-4 bg-slate-700 rounded-lg">
            <div className="flex items-center space-x-3">
              <MessageSquare className="h-6 w-6 text-green-400" />
              <div>
                <p className="font-medium text-white">Slack</p>
                <p className="text-sm text-slate-400">Team Notifications</p>
              </div>
            </div>
            <div className={`h-2 w-2 rounded-full ${notificationChannels.slack ? 'bg-emerald-400' : 'bg-slate-500'}`} />
          </div>

          <div className="flex items-center justify-between p-4 bg-slate-700 rounded-lg">
            <div className="flex items-center space-x-3">
              <Monitor className="h-6 w-6 text-orange-400" />
              <div>
                <p className="font-medium text-white">Grafana</p>
                <p className="text-sm text-slate-400">Dashboard Alerts</p>
              </div>
            </div>
            <div className={`h-2 w-2 rounded-full ${notificationChannels.webhook ? 'bg-emerald-400' : 'bg-slate-500'}`} />
          </div>
        </div>
      </div>

      {/* Alert Feed */}
      <div className="bg-slate-800 rounded-xl border border-slate-700">
        <div className="p-6 border-b border-slate-700">
          <h3 className="text-lg font-semibold text-white">Active Alerts</h3>
        </div>
        <div className="divide-y divide-slate-700">
          {alerts.length === 0 ? (
            <div className="p-8 text-center">
              <Shield className="h-12 w-12 text-emerald-400 mx-auto mb-4" />
              <p className="text-slate-400">No active alerts. System is secure.</p>
            </div>
          ) : (
            alerts.slice(0, 10).map((alert) => (
              <div
                key={alert.id}
                className={`p-6 border-l-4 ${getSeverityColor(alert.severity)}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      {getStatusIcon(alert.status)}
                      <h4 className="font-semibold text-white">{alert.type} Detected</h4>
                      <span className={`px-2 py-1 text-xs font-medium rounded ${
                        alert.severity === 'Critical' ? 'bg-red-600 text-white' :
                        alert.severity === 'High' ? 'bg-orange-600 text-white' :
                        alert.severity === 'Medium' ? 'bg-yellow-600 text-black' :
                        'bg-green-600 text-white'
                      }`}>
                        {alert.severity}
                      </span>
                    </div>
                    <p className="text-slate-300 mb-2">
                      Suspicious activity from <span className="font-mono text-emerald-400">{alert.source}</span>
                    </p>
                    <div className="flex items-center space-x-4 text-sm text-slate-400">
                      <span>Confidence: {alert.confidence}%</span>
                      <span>Time: {alert.timestamp}</span>
                      <span>Status: {alert.status}</span>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2 ml-4">
                    {!alert.acknowledged && (
                      <button
                        onClick={() => acknowledgeAlert(alert.id)}
                        className="px-3 py-1 bg-yellow-600 hover:bg-yellow-700 text-white text-sm rounded transition-colors"
                      >
                        Acknowledge
                      </button>
                    )}
                    <button
                      onClick={() => dismissAlert(alert.id)}
                      className="px-3 py-1 bg-slate-600 hover:bg-slate-500 text-white text-sm rounded transition-colors"
                    >
                      Dismiss
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Alert Rules */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Alert Rules Configuration</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            { rule: 'DDoS Detection', threshold: '> 1000 req/s', enabled: true },
            { rule: 'Port Scan Alert', threshold: '> 10 ports/min', enabled: true },
            { rule: 'Malware Detection', threshold: 'Confidence > 85%', enabled: true },
            { rule: 'Anomaly Alert', threshold: 'Score > 0.8', enabled: false },
            { rule: 'Brute Force', threshold: '> 5 failed attempts', enabled: true },
            { rule: 'Data Exfiltration', threshold: '> 100MB/min', enabled: true },
          ].map((rule) => (
            <div key={rule.rule} className="flex items-center justify-between p-4 bg-slate-700 rounded-lg">
              <div>
                <p className="font-medium text-white">{rule.rule}</p>
                <p className="text-sm text-slate-400">{rule.threshold}</p>
              </div>
              <div className={`flex items-center space-x-2 ${rule.enabled ? 'text-emerald-400' : 'text-slate-500'}`}>
                <div className={`h-2 w-2 rounded-full ${rule.enabled ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                <span className="text-sm">{rule.enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default AlertingSystem;