import React, { useEffect, useState } from 'react';
import { Server, Search, RefreshCw, Globe, Shield } from 'lucide-react';
import toast from 'react-hot-toast';
import api from '../services/api';
import type { EC2Instance } from '../types';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';

export const EC2Inventory: React.FC = () => {
  const [instances, setInstances] = useState<EC2Instance[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState<string>('');
  const [selectedRegion, setSelectedRegion] = useState<string>('all');
  const [selectedState, setSelectedState] = useState<string>('all');

  const fetchInstances = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getInstances();
      setInstances(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load EC2 instances');
      toast.error('Failed to load EC2 inventory');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInstances();
  }, []);

  // Filter options
  const regions = Array.from(new Set(instances.map((i) => i.region))).filter(Boolean);
  const states = Array.from(new Set(instances.map((i) => i.state))).filter(Boolean);

  const filteredInstances = instances.filter((i) => {
    const matchesSearch =
      i.instance_id.toLowerCase().includes(search.toLowerCase()) ||
      i.name.toLowerCase().includes(search.toLowerCase()) ||
      (i.public_ip && i.public_ip.includes(search)) ||
      (i.private_ip && i.private_ip.includes(search));

    const matchesRegion = selectedRegion === 'all' || i.region === selectedRegion;
    const matchesState = selectedState === 'all' || i.state.toLowerCase() === selectedState.toLowerCase();

    return matchesSearch && matchesRegion && matchesState;
  });

  if (loading) {
    return <LoadingSpinner text="Scanning EC2 inventory across AWS regions..." />;
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchInstances} />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl shadow-sm">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Server className="h-6 w-6 text-indigo-400" />
            EC2 Instance Inventory
          </h1>
          <p className="text-xs text-slate-400">
            Discovered instances, public/private IP addresses, and associated security groups
          </p>
        </div>

        <button
          onClick={fetchInstances}
          className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 flex items-center gap-2 transition"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh Inventory
        </button>
      </div>

      {/* Filter Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search by ID, Name, or IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
          />
        </div>

        <div>
          <select
            value={selectedRegion}
            onChange={(e) => setSelectedRegion(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All Regions ({regions.length})</option>
            {regions.map((reg) => (
              <option key={reg} value={reg}>
                {reg}
              </option>
            ))}
          </select>
        </div>

        <div>
          <select
            value={selectedState}
            onChange={(e) => setSelectedState(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All States</option>
            {states.map((st) => (
              <option key={st} value={st}>
                {st.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Table */}
      {filteredInstances.length > 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Instance ID</th>
                  <th className="py-3 px-4">Name / Tag</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Region</th>
                  <th className="py-3 px-4">State</th>
                  <th className="py-3 px-4">Public IP</th>
                  <th className="py-3 px-4">Private IP</th>
                  <th className="py-3 px-4">Security Groups</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {filteredInstances.map((inst) => {
                  const isRunning = inst.state.toLowerCase() === 'running';
                  const isStopped = inst.state.toLowerCase() === 'stopped';
                  return (
                    <tr key={inst.instance_id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 font-mono font-semibold text-indigo-400">
                        {inst.instance_id}
                      </td>
                      <td className="py-3 px-4 font-medium text-slate-200">
                        {inst.name || <span className="text-slate-500 italic">None</span>}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">{inst.instance_type}</td>
                      <td className="py-3 px-4 text-slate-300">{inst.region}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            isRunning
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : isStopped
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {inst.state}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {inst.public_ip ? (
                          <span className="inline-flex items-center gap-1 font-mono text-rose-400 bg-rose-950/40 px-2 py-0.5 rounded border border-rose-900/60">
                            <Globe className="h-3 w-3" />
                            {inst.public_ip}
                          </span>
                        ) : (
                          <span className="text-slate-500 italic">None</span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {inst.private_ip || <span className="text-slate-500 italic">None</span>}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1 max-w-xs">
                          {inst.security_group_names && inst.security_group_names.length > 0 ? (
                            inst.security_group_names.map((sgName, idx) => (
                              <span
                                key={idx}
                                className="inline-flex items-center gap-1 bg-slate-800 text-slate-300 text-[10px] px-2 py-0.5 rounded border border-slate-700"
                              >
                                <Shield className="h-2.5 w-2.5 text-indigo-400" />
                                {sgName}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-500 italic">None</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <EmptyState
          icon={Server}
          title="No EC2 Instances Found"
          description={
            instances.length === 0
              ? 'No EC2 instances were detected in your enabled AWS regions. Run a full scan or verify region permissions.'
              : 'No instances match the current search filters.'
          }
        />
      )}
    </div>
  );
};

export default EC2Inventory;

