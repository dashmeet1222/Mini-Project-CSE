import React, { useState, useEffect } from 'react';
import { Zap, Target, AlertTriangle, TrendingUp, Clock, Shield } from 'lucide-react';

interface InferenceEngineProps {
  threats: any[];
}

const InferenceEngine: React.FC<InferenceEngineProps> = ({ threats }) => {
  const [inferenceStats, setInferenceStats] = useState({
    predictionsPerSecond: 0,
    avgLatency: 0,
    modelLoad: 0,
    queueSize: 0,
  });

  const [detectionResults, setDetectionResults] = useState<any[]>([]);

  useEffect(() => {
    const interval = setInterval(() => {
      setInferenceStats({
        predictionsPerSecond: Math.floor(Math.random() * 500) + 800,
        avgLatency: Math.floor(Math.random() * 10) + 15,
        modelLoad: Math.floor(Math.random() * 30) + 65,
        queueSize: Math.floor(Math.random() * 100),
      });
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Convert threats to detection results with confidence scores
    const results = threats.map(threat => ({
      ...threat,
      prediction: threat.type,
      modelConfidence: threat.confidence,
      riskScore: getRiskScore(threat.severity),
      features: generateFeatures(),
    }));
    setDetectionResults(results);
  }, [threats]);

  const getRiskScore = (severity: string) => {
    switch (severity) {
      case 'Critical': return 95 + Math.floor(Math.random() * 5);
      case 'High': return 75 + Math.floor(Math.random() * 20);
      case 'Medium': return 45 + Math.floor(Math.random() * 30);
      default: return Math.floor(Math.random() * 45);
    }
  };

  const generateFeatures = () => ({
    packetSize: Math.floor(Math.random() * 1500) + 64,
    flowDuration: Math.floor(Math.random() * 1000) + 100,
    byteRate: Math.floor(Math.random() * 10000) + 1000,
    connections: Math.floor(Math.random() * 100) + 1,
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-400 bg-red-400';
      case 'High': return 'text-orange-400 bg-orange-400';
      case 'Medium': return 'text-yellow-400 bg-yellow-400';
      default: return 'text-green-400 bg-green-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Real-time Inference Engine</h2>
        <div className="flex items-center space-x-2">
          <div className="h-2 w-2 bg-emerald-400 rounded-full animate-pulse" />
          <span className="text-sm text-slate-300">Model Active</span>
        </div>
      </div>

      {/* Performance Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Predictions/sec</p>
              <p className="text-2xl font-bold text-emerald-400">{inferenceStats.predictionsPerSecond}</p>
            </div>
            <Zap className="h-8 w-8 text-emerald-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Avg Latency</p>
              <p className="text-2xl font-bold text-blue-400">{inferenceStats.avgLatency}ms</p>
            </div>
            <Clock className="h-8 w-8 text-blue-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Model Load</p>
              <p className="text-2xl font-bold text-purple-400">{inferenceStats.modelLoad}%</p>
            </div>
            <TrendingUp className="h-8 w-8 text-purple-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Queue Size</p>
              <p className="text-2xl font-bold text-orange-400">{inferenceStats.queueSize}</p>
            </div>
            <Target className="h-8 w-8 text-orange-400" />
          </div>
        </div>
      </div>

      {/* Model Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Active Models</h3>
          <div className="space-y-4">
            {[
              { name: 'Random Forest Classifier', type: 'Primary', load: 75, accuracy: 94.7, status: 'Active' },
              { name: 'Isolation Forest', type: 'Anomaly Detection', load: 45, accuracy: 92.1, status: 'Active' },
              { name: 'One-Class SVM', type: 'Outlier Detection', load: 30, accuracy: 89.3, status: 'Active' },
            ].map((model) => (
              <div key={model.name} className="p-4 bg-slate-700 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-medium text-white">{model.name}</h4>
                  <span className={`px-2 py-1 text-xs font-medium rounded ${
                    model.type === 'Primary' ? 'bg-emerald-600 text-white' :
                    model.type === 'Anomaly Detection' ? 'bg-blue-600 text-white' :
                    'bg-purple-600 text-white'
                  }`}>
                    {model.type}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <p className="text-slate-400 text-sm">Load</p>
                    <div className="flex items-center space-x-2">
                      <div className="flex-1 bg-slate-600 rounded-full h-1">
                        <div
                          className="bg-emerald-400 h-1 rounded-full"
                          style={{ width: `${model.load}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-300">{model.load}%</span>
                    </div>
                  </div>
                  <div>
                    <p className="text-slate-400 text-sm">Accuracy</p>
                    <p className="text-emerald-400 font-medium">{model.accuracy}%</p>
                  </div>
                  <div>
                    <p className="text-slate-400 text-sm">Status</p>
                    <div className="flex items-center space-x-1">
                      <div className="h-2 w-2 bg-emerald-400 rounded-full" />
                      <span className="text-xs text-emerald-400">Active</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Detection Categories</h3>
          <div className="space-y-3">
            {[
              { category: 'DDoS Attacks', count: 15, percentage: 35 },
              { category: 'Port Scanning', count: 12, percentage: 28 },
              { category: 'SQL Injection', count: 8, percentage: 19 },
              { category: 'Malware', count: 5, percentage: 12 },
              { category: 'Other', count: 3, percentage: 6 },
            ].map((item) => (
              <div key={item.category} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{
                      backgroundColor: item.category === 'DDoS Attacks' ? '#10b981' :
                                     item.category === 'Port Scanning' ? '#3b82f6' :
                                     item.category === 'SQL Injection' ? '#8b5cf6' :
                                     item.category === 'Malware' ? '#ef4444' : '#6b7280'
                    }}
                  />
                  <span className="text-slate-300">{item.category}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-white font-medium">{item.count}</span>
                  <span className="text-slate-400 text-sm">({item.percentage}%)</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Real-time Detection Results */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
        <div className="p-6 border-b border-slate-700">
          <h3 className="text-lg font-semibold text-white">Live Detection Results</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Time</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Prediction</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Confidence</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Risk Score</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {detectionResults.slice(0, 10).map((result) => {
                const severityColors = getSeverityColor(result.severity);
                return (
                  <tr key={result.id} className="hover:bg-slate-700 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {result.timestamp}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {result.source}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">
                      {result.prediction}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-emerald-400">
                      {result.modelConfidence}%
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-orange-400">
                      {result.riskScore}/100
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        <div className={`h-2 w-2 rounded-full ${severityColors.split(' ')[1]}`} />
                        <span className={`text-sm ${severityColors.split(' ')[0]}`}>
                          {result.severity}
                        </span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default InferenceEngine;