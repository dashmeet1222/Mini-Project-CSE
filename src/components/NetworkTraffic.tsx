import React, { useState, useEffect } from 'react';
import { Activity, Globe, Server, Wifi, Download, Upload } from 'lucide-react';

const NetworkTraffic: React.FC = () => {
  const [trafficData, setTrafficData] = useState<any[]>([]);
  const [totalPackets, setTotalPackets] = useState(0);
  const [bandwidth, setBandwidth] = useState({ down: 0, up: 0 });

  useEffect(() => {
    const interval = setInterval(() => {
      const newPacket = {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        source: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        destination: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        protocol: ['TCP', 'UDP', 'HTTP', 'HTTPS'][Math.floor(Math.random() * 4)],
        size: Math.floor(Math.random() * 1500) + 64,
        port: Math.floor(Math.random() * 65535),
      };

      setTrafficData(prev => [newPacket, ...prev.slice(0, 99)]);
      setTotalPackets(prev => prev + 1);
      setBandwidth({
        down: Math.floor(Math.random() * 1000) + 500,
        up: Math.floor(Math.random() * 500) + 100,
      });
    }, 100);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Network Traffic Monitoring</h2>
        <div className="flex items-center space-x-2">
          <div className="h-2 w-2 bg-emerald-400 rounded-full animate-pulse" />
          <span className="text-sm text-slate-300">Live Capture Active</span>
        </div>
      </div>

      {/* Traffic Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Total Packets</p>
              <p className="text-2xl font-bold text-white">{totalPackets.toLocaleString()}</p>
            </div>
            <Activity className="h-8 w-8 text-emerald-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Download</p>
              <p className="text-2xl font-bold text-blue-400">{bandwidth.down} Mbps</p>
            </div>
            <Download className="h-8 w-8 text-blue-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Upload</p>
              <p className="text-2xl font-bold text-purple-400">{bandwidth.up} Mbps</p>
            </div>
            <Upload className="h-8 w-8 text-purple-400" />
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Active Connections</p>
              <p className="text-2xl font-bold text-orange-400">1,247</p>
            </div>
            <Wifi className="h-8 w-8 text-orange-400" />
          </div>
        </div>
      </div>

      {/* Capture Methods */}
      <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
        <h3 className="text-lg font-semibold mb-4 text-white">Capture Configuration</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex items-center space-x-3 p-4 bg-slate-700 rounded-lg">
            <Globe className="h-6 w-6 text-emerald-400" />
            <div>
              <p className="font-medium text-white">Network TAP</p>
              <p className="text-sm text-slate-400">Hardware-based capture</p>
            </div>
            <div className="ml-auto">
              <div className="h-2 w-2 bg-emerald-400 rounded-full" />
            </div>
          </div>
          
          <div className="flex items-center space-x-3 p-4 bg-slate-700 rounded-lg">
            <Server className="h-6 w-6 text-blue-400" />
            <div>
              <p className="font-medium text-white">SPAN Port</p>
              <p className="text-sm text-slate-400">Switch mirroring</p>
            </div>
            <div className="ml-auto">
              <div className="h-2 w-2 bg-blue-400 rounded-full" />
            </div>
          </div>
          
          <div className="flex items-center space-x-3 p-4 bg-slate-700 rounded-lg">
            <Activity className="h-6 w-6 text-purple-400" />
            <div>
              <p className="font-medium text-white">Software Tap</p>
              <p className="text-sm text-slate-400">Agent-based capture</p>
            </div>
            <div className="ml-auto">
              <div className="h-2 w-2 bg-purple-400 rounded-full" />
            </div>
          </div>
        </div>
      </div>

      {/* Live Traffic Table */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
        <div className="p-6 border-b border-slate-700">
          <h3 className="text-lg font-semibold text-white">Live Traffic Stream</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Time</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Destination</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Protocol</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Port</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase">Size</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {trafficData.slice(0, 20).map((packet) => (
                <tr key={packet.id} className="hover:bg-slate-700 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                    {packet.timestamp}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                    {packet.source}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                    {packet.destination}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 text-xs font-medium rounded ${
                      packet.protocol === 'HTTPS' ? 'bg-emerald-600 text-white' :
                      packet.protocol === 'HTTP' ? 'bg-blue-600 text-white' :
                      packet.protocol === 'TCP' ? 'bg-purple-600 text-white' :
                      'bg-orange-600 text-white'
                    }`}>
                      {packet.protocol}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                    {packet.port}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                    {packet.size} bytes
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default NetworkTraffic;