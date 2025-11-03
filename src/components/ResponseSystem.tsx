import React, { useState, useEffect } from 'react';
import { Shield, Zap, Ban, AlertTriangle, CheckCircle, Clock, Settings } from 'lucide-react';

interface ResponseSystemProps {
  threats: any[];
}

const ResponseSystem: React.FC<ResponseSystemProps> = ({ threats }) => {
  const [automatedResponses, setAutomatedResponses] = useState<any[]>([]);
  const [responseStats, setResponseStats] = useState({
    blocked: 0,
    quarantined: 0,
    investigated: 0,
    resolved: 0,
  });

  useEffect(() => {
    // Generate automated responses based on threats
    const responses = threats.map((threat, index) => ({
      id: `response-${threat.id}-${index}`,
      threatId: threat.id,
      action: getAutomatedAction(threat.severity),
      status: getResponseStatus(),
      timestamp: new Date().toLocaleTimeString(),
      details: `Automated response to ${threat.type} from ${threat.source}`,
      executionTime: Math.floor(Math.random() * 500) + 100,
    }));

    setAutomatedResponses(responses);

    // Update stats
    setResponseStats({
      blocked: responses.filter(r => r.action === 'Block IP').length,
      quarantined: responses.filter(r => r.action === 'Quarantine').length,
      investigated: responses.filter(r => r.action === 'Investigate').length,
      resolved: responses.filter(r => r.status === 'Completed').length,
    });
  }, [threats]);

  const getAutomatedAction = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'Block IP';
      case 'High': return 'Quarantine';
      case 'Medium': return 'Rate Limit';
      default: return 'Monitor';
    }
  };

  const getResponseStatus = () => {
    const statuses = ['Pending', 'Executing', 'Completed', 'Failed'];
    return statuses[Math.floor(Math.random() * statuses.length)];
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'Block IP': return <Ban className="h-4 w-4 text-red-400" />;
      case 'Quarantine': return <Shield className="h-4 w-4 text-orange-400" />;
      case 'Rate Limit': return <Clock className="h-4 w-4 text-yellow-400" />;
      case 'Investigate': return <AlertTriangle className="h-4 w-4 text-blue-400" />;
      default: return <Settings className="h-4 w-4 text-slate-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Completed': return 'text-emerald-400 bg-emerald-400';
      case 'Executing': return 'text-blue-400 bg-blue-400';
      case 'Pending': return 'text-yellow-400 bg-yellow-400';
      case 'Failed': return 'text-red-400 bg-red-400';
      default: return 'text-slate-400 bg-slate-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Automated Response System</h2>
        <div className="flex items-center space-x-2">
          <div className="h-2 w-2 bg-emerald-400 rounded-full animate-pulse" />
          <span className="text-sm text-slate-300">Response Engine Active</span>
        </div>
      </div>

      {/* Response Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">IPs Blocked</p>
              <p className="text-2xl font-bold text-red-400">{responseStats.blocked}</p>
            </div>
            <Ban className="h-8 w-8 text-red-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Quarantined</p>
              <p className="text-2xl font-bold text-orange-400">{responseStats.quarantined}</p>
            </div>
            <Shield className="h-8 w-8 text-orange-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Under Investigation</p>
              <p className="text-2xl font-bold text-blue-400">{responseStats.investigated}</p>
            </div>
            <AlertTriangle className="h-8 w-8 text-blue-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Resolved</p>
              <p className="text-2xl font-bold text-emerald-400">{responseStats.resolved}</p>
            </div>
            <CheckCircle className="h-8 w-8 text-emerald-400" />
          </div>
        </div>
      </div>

      {/* Response Types */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Response Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-slate-700 rounded-lg">
            <div className="flex items-center space-x-3 mb-3">
              <Ban className="h-6 w-6 text-red-400" />
              <h4 className="font-medium text-white">Firewall Block</h4>
            </div>
            <p className="text-sm text-slate-400 mb-2">Immediate IP blocking for critical threats</p>
            <div className="text-xs text-red-400">Auto-triggered on Critical severity</div>
          </div>

          <div className="p-4 bg-slate-700 rounded-lg">
            <div className="flex items-center space-x-3 mb-3">
              <Shield className="h-6 w-6 text-orange-400" />
              <h4 className="font-medium text-white">Quarantine</h4>
            </div>
            <p className="text-sm text-slate-400 mb-2">Isolate suspicious traffic for analysis</p>
            <div className="text-xs text-orange-400">Auto-triggered on High severity</div>
          </div>

          <div className="p-4 bg-slate-700 rounded-lg">
            <div className="flex items-center space-x-3 mb-3">
              <Zap className="h-6 w-6 text-purple-400" />
              <h4 className="font-medium text-white">Rate Limiting</h4>
            </div>
            <p className="text-sm text-slate-400 mb-2">Throttle suspicious connections</p>
            <div className="text-xs text-purple-400">Auto-triggered on Medium severity</div>
          </div>
        </div>
      </div>

      {/* Active Responses */}
      <div className="bg-slate-800 rounded-xl border border-slate-700">
        <div className="p-6 border-b border-slate-700">
          <h3 className="text-lg font-semibold text-white">Active Response Log</h3>
        </div>
        <div className="divide-y divide-slate-700">
          {automatedResponses.length === 0 ? (
            <div className="p-8 text-center">
              <Shield className="h-12 w-12 text-emerald-400 mx-auto mb-4" />
              <p className="text-slate-400">No active responses. System is secure.</p>
            </div>
          ) : (
            automatedResponses.slice(0, 10).map((response) => {
              const statusColors = getStatusColor(response.status);
              return (
                <div key={response.id} className="p-6">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-4">
                      {getActionIcon(response.action)}
                      <div>
                        <h4 className="font-semibold text-white mb-1">{response.action}</h4>
                        <p className="text-slate-300 text-sm mb-2">{response.details}</p>
                        <div className="flex items-center space-x-4 text-xs text-slate-400">
                          <span>Time: {response.timestamp}</span>
                          <span>Execution: {response.executionTime}ms</span>
                          <span>Threat ID: {response.threatId}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className={`h-2 w-2 rounded-full ${statusColors.split(' ')[1]}`} />
                      <span className={`text-sm ${statusColors.split(' ')[0]}`}>
                        {response.status}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Playbooks */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Response Playbooks</h3>
          <div className="space-y-4">
            {[
              { name: 'DDoS Mitigation', steps: 4, enabled: true },
              { name: 'Malware Containment', steps: 6, enabled: true },
              { name: 'Data Breach Response', steps: 8, enabled: true },
              { name: 'APT Investigation', steps: 10, enabled: false },
            ].map((playbook) => (
              <div key={playbook.name} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                <div>
                  <p className="font-medium text-white">{playbook.name}</p>
                  <p className="text-sm text-slate-400">{playbook.steps} automated steps</p>
                </div>
                <div className={`flex items-center space-x-2 ${playbook.enabled ? 'text-emerald-400' : 'text-slate-500'}`}>
                  <div className={`h-2 w-2 rounded-full ${playbook.enabled ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                  <span className="text-sm">{playbook.enabled ? 'Active' : 'Disabled'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Integration Status</h3>
          <div className="space-y-4">
            {[
              { system: 'Firewall', type: 'Palo Alto', status: 'Connected' },
              { system: 'SIEM', type: 'Splunk', status: 'Connected' },
              { system: 'EDR', type: 'CrowdStrike', status: 'Connected' },
              { system: 'Network Segmentation', type: 'Cisco ACI', status: 'Disconnected' },
            ].map((integration) => (
              <div key={integration.system} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                <div>
                  <p className="font-medium text-white">{integration.system}</p>
                  <p className="text-sm text-slate-400">{integration.type}</p>
                </div>
                <div className={`flex items-center space-x-2 ${
                  integration.status === 'Connected' ? 'text-emerald-400' : 'text-red-400'
                }`}>
                  <div className={`h-2 w-2 rounded-full ${
                    integration.status === 'Connected' ? 'bg-emerald-400' : 'bg-red-400'
                  }`} />
                  <span className="text-sm">{integration.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResponseSystem;