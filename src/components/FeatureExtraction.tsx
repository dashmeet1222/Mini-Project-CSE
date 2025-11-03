import React, { useState, useEffect } from 'react';
import { Settings, Database, TrendingUp, FileText, Zap, Filter } from 'lucide-react';

const FeatureExtraction: React.FC = () => {
  const [processingStats, setProcessingStats] = useState({
    packetsProcessed: 0,
    featuresExtracted: 0,
    processingRate: 0,
  });

  const [pipelineStatus, setPipelineStatus] = useState({
    preprocessing: 'active',
    featureExtraction: 'active',
    normalization: 'active',
    storage: 'active',
  });

  useEffect(() => {
    const interval = setInterval(() => {
      setProcessingStats(prev => ({
        packetsProcessed: prev.packetsProcessed + Math.floor(Math.random() * 100) + 50,
        featuresExtracted: prev.featuresExtracted + Math.floor(Math.random() * 20) + 10,
        processingRate: Math.floor(Math.random() * 500) + 1000,
      }));
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  const features = [
    { name: 'Packet Size', value: '1,247 avg', category: 'Network' },
    { name: 'Flow Duration', value: '12.5ms avg', category: 'Temporal' },
    { name: 'Protocol Distribution', value: '67% TCP', category: 'Protocol' },
    { name: 'Port Frequency', value: '443 most common', category: 'Network' },
    { name: 'Bytes per Second', value: '2.4MB/s', category: 'Throughput' },
    { name: 'Inter-arrival Time', value: '0.8ms avg', category: 'Temporal' },
    { name: 'Payload Entropy', value: '7.2 bits', category: 'Content' },
    { name: 'Flag Patterns', value: 'SYN/ACK 34%', category: 'Protocol' },
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-emerald-400 bg-emerald-400';
      case 'warning': return 'text-yellow-400 bg-yellow-400';
      case 'error': return 'text-red-400 bg-red-400';
      default: return 'text-slate-400 bg-slate-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Feature Extraction Pipeline</h2>
        <div className="flex items-center space-x-2">
          <div className="h-2 w-2 bg-emerald-400 rounded-full animate-pulse" />
          <span className="text-sm text-slate-300">Pipeline Active</span>
        </div>
      </div>

      {/* Processing Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Packets Processed</p>
              <p className="text-2xl font-bold text-emerald-400">{processingStats.packetsProcessed.toLocaleString()}</p>
            </div>
            <Settings className="h-8 w-8 text-emerald-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Features Extracted</p>
              <p className="text-2xl font-bold text-blue-400">{processingStats.featuresExtracted.toLocaleString()}</p>
            </div>
            <TrendingUp className="h-8 w-8 text-blue-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Processing Rate</p>
              <p className="text-2xl font-bold text-purple-400">{processingStats.processingRate}/s</p>
            </div>
            <Zap className="h-8 w-8 text-purple-400" />
          </div>
        </div>
      </div>

      {/* Pipeline Status */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Pipeline Components</h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[
            { name: 'Preprocessing', status: pipelineStatus.preprocessing, icon: Filter },
            { name: 'Feature Extraction', status: pipelineStatus.featureExtraction, icon: Settings },
            { name: 'Normalization', status: pipelineStatus.normalization, icon: TrendingUp },
            { name: 'Storage', status: pipelineStatus.storage, icon: Database },
          ].map((component) => {
            const Icon = component.icon;
            const colorClass = getStatusColor(component.status);
            return (
              <div key={component.name} className="p-4 bg-slate-700 rounded-lg">
                <div className="flex items-center justify-between mb-3">
                  <Icon className={`h-6 w-6 ${colorClass.split(' ')[0]}`} />
                  <div className={`h-2 w-2 rounded-full ${colorClass.split(' ')[1]}`} />
                </div>
                <h4 className="font-medium text-white">{component.name}</h4>
                <p className="text-sm text-slate-400 capitalize">{component.status}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Feature Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Extracted Features</h3>
          <div className="space-y-3">
            {features.map((feature) => (
              <div key={feature.name} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                <div>
                  <p className="font-medium text-white">{feature.name}</p>
                  <p className="text-sm text-slate-400">{feature.category}</p>
                </div>
                <div className="text-right">
                  <p className="text-sm font-medium text-emerald-400">{feature.value}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 text-white">Storage Formats</h3>
          <div className="space-y-4">
            <div className="p-4 bg-slate-700 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-medium text-white">CSV Export</h4>
                <FileText className="h-5 w-5 text-emerald-400" />
              </div>
              <p className="text-sm text-slate-400">Structured data for analysis tools</p>
              <div className="mt-2 bg-slate-800 p-2 rounded text-xs font-mono text-emerald-400">
                timestamp,src_ip,dst_ip,protocol,packet_size,flow_duration
              </div>
            </div>

            <div className="p-4 bg-slate-700 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-medium text-white">Parquet Files</h4>
                <Database className="h-5 w-5 text-blue-400" />
              </div>
              <p className="text-sm text-slate-400">Compressed columnar storage</p>
              <div className="mt-2 text-xs text-blue-400">
                Optimized for ML pipelines and analytics
              </div>
            </div>

            <div className="p-4 bg-slate-700 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-medium text-white">Database</h4>
                <Database className="h-5 w-5 text-purple-400" />
              </div>
              <p className="text-sm text-slate-400">Real-time feature store</p>
              <div className="mt-2 text-xs text-purple-400">
                PostgreSQL with time-series optimization
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Feature Engineering */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Feature Engineering Pipeline</h3>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {[
            { step: 'Raw Packets', status: 'complete', description: 'Network traffic capture' },
            { step: 'Preprocessing', status: 'active', description: 'Data cleaning and filtering' },
            { step: 'Feature Extraction', status: 'active', description: 'Statistical feature computation' },
            { step: 'Normalization', status: 'active', description: 'Feature scaling and encoding' },
            { step: 'Storage', status: 'active', description: 'Persistent feature store' },
          ].map((step, index) => (
            <div key={step.step} className="relative">
              <div className={`p-4 rounded-lg text-center ${
                step.status === 'complete' ? 'bg-emerald-600/20 border border-emerald-400' :
                step.status === 'active' ? 'bg-blue-600/20 border border-blue-400' :
                'bg-slate-700 border border-slate-600'
              }`}>
                <h4 className={`font-medium ${
                  step.status === 'complete' ? 'text-emerald-400' :
                  step.status === 'active' ? 'text-blue-400' :
                  'text-slate-400'
                }`}>
                  {step.step}
                </h4>
                <p className="text-xs text-slate-400 mt-1">{step.description}</p>
              </div>
              {index < 4 && (
                <div className="absolute top-1/2 -right-2 w-4 h-0.5 bg-slate-600 transform -translate-y-1/2" />
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default FeatureExtraction;