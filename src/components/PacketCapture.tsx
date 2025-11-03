import React, { useState, useEffect } from 'react';
import { Database, Play, Pause, Download, FileText, Settings } from 'lucide-react';

const PacketCapture: React.FC = () => {
  const [isCapturing, setIsCapturing] = useState(true);
  const [captureStats, setCaptureStats] = useState({
    packetsProcessed: 0,
    dataSize: 0,
    duration: 0,
  });

  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    if (isCapturing) {
      interval = setInterval(() => {
        setCaptureStats(prev => ({
          packetsProcessed: prev.packetsProcessed + Math.floor(Math.random() * 50) + 10,
          dataSize: prev.dataSize + Math.floor(Math.random() * 1000) + 500,
          duration: prev.duration + 1,
        }));
      }, 1000);
    }

    return () => clearInterval(interval);
  }, [isCapturing]);

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDuration = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Packet Capture System</h2>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsCapturing(!isCapturing)}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg font-medium ${
              isCapturing 
                ? 'bg-red-600 hover:bg-red-700 text-white' 
                : 'bg-emerald-600 hover:bg-emerald-700 text-white'
            }`}
          >
            {isCapturing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            <span>{isCapturing ? 'Stop' : 'Start'} Capture</span>
          </button>
        </div>
      </div>

      {/* Capture Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Packets Captured</p>
              <p className="text-2xl font-bold text-emerald-400">{captureStats.packetsProcessed.toLocaleString()}</p>
            </div>
            <Database className="h-8 w-8 text-emerald-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Data Captured</p>
              <p className="text-2xl font-bold text-blue-400">{formatFileSize(captureStats.dataSize)}</p>
            </div>
            <FileText className="h-8 w-8 text-blue-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Duration</p>
              <p className="text-2xl font-bold text-purple-400">{formatDuration(captureStats.duration)}</p>
            </div>
            <Settings className="h-8 w-8 text-purple-400" />
          </div>
        </div>
      </div>

      {/* Capture Tools */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Capture Tools Configuration</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-slate-700 rounded-lg">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium text-white">tcpdump</h4>
              <div className="h-2 w-2 bg-emerald-400 rounded-full" />
            </div>
            <p className="text-sm text-slate-400 mb-3">Command-line packet analyzer</p>
            <div className="bg-slate-900 p-3 rounded text-xs font-mono text-emerald-400">
              tcpdump -i eth0 -w capture.pcap
            </div>
          </div>

          <div className="p-4 bg-slate-700 rounded-lg">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium text-white">tshark</h4>
              <div className="h-2 w-2 bg-blue-400 rounded-full" />
            </div>
            <p className="text-sm text-slate-400 mb-3">Wireshark terminal interface</p>
            <div className="bg-slate-900 p-3 rounded text-xs font-mono text-blue-400">
              tshark -i eth0 -f "tcp port 80"
            </div>
          </div>

          <div className="p-4 bg-slate-700 rounded-lg">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium text-white">Suricata</h4>
              <div className="h-2 w-2 bg-purple-400 rounded-full" />
            </div>
            <p className="text-sm text-slate-400 mb-3">Network security monitoring</p>
            <div className="bg-slate-900 p-3 rounded text-xs font-mono text-purple-400">
              suricata -c /etc/suricata/suricata.yaml -i eth0
            </div>
          </div>
        </div>
      </div>

      {/* Capture Filters */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Active Filters</h3>
        <div className="space-y-3">
          {[
            { name: 'HTTP Traffic', filter: 'tcp port 80 or tcp port 8080', active: true },
            { name: 'HTTPS Traffic', filter: 'tcp port 443', active: true },
            { name: 'DNS Queries', filter: 'udp port 53', active: false },
            { name: 'SSH Connections', filter: 'tcp port 22', active: true },
            { name: 'FTP Traffic', filter: 'tcp port 21', active: false },
          ].map((filterItem) => (
            <div key={filterItem.name} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
              <div>
                <p className="font-medium text-white">{filterItem.name}</p>
                <p className="text-sm text-slate-400 font-mono">{filterItem.filter}</p>
              </div>
              <div className={`flex items-center space-x-2 ${filterItem.active ? 'text-emerald-400' : 'text-slate-500'}`}>
                <div className={`h-2 w-2 rounded-full ${filterItem.active ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                <span className="text-sm">{filterItem.active ? 'Active' : 'Inactive'}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Export Options */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Export Captured Data</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button className="flex items-center justify-center space-x-2 p-4 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors">
            <Download className="h-5 w-5 text-emerald-400" />
            <span className="text-white">Export as PCAP</span>
          </button>
          
          <button className="flex items-center justify-center space-x-2 p-4 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors">
            <FileText className="h-5 w-5 text-blue-400" />
            <span className="text-white">Export as CSV</span>
          </button>
          
          <button className="flex items-center justify-center space-x-2 p-4 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors">
            <Database className="h-5 w-5 text-purple-400" />
            <span className="text-white">Export to Database</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default PacketCapture;