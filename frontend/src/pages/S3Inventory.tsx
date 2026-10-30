import React, { useEffect, useState } from 'react';
import { Database, Search, RefreshCw, Lock, Unlock, ShieldCheck, ShieldAlert, Check, X } from 'lucide-react';
import toast from 'react-hot-toast';
import api from '../services/api';
import type { S3Bucket } from '../types';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';

export const S3Inventory: React.FC = () => {
  const [buckets, setBuckets] = useState<S3Bucket[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState<string>('');
  const [publicFilter, setPublicFilter] = useState<string>('all');
  const [encryptionFilter, setEncryptionFilter] = useState<string>('all');

  const fetchBuckets = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getBuckets();
      setBuckets(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load S3 buckets');
      toast.error('Failed to load S3 inventory');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBuckets();
  }, []);

  const filteredBuckets = buckets.filter((b) => {
    const matchesSearch = b.name.toLowerCase().includes(search.toLowerCase());
    const matchesPublic =
      publicFilter === 'all'
        ? true
        : publicFilter === 'public'
        ? b.is_public
        : !b.is_public;

    const matchesEnc =
      encryptionFilter === 'all'
        ? true
        : encryptionFilter === 'encrypted'
        ? b.encryption_enabled
        : !b.encryption_enabled;

    return matchesSearch && matchesPublic && matchesEnc;
  });

  if (loading) {
    return <LoadingSpinner text="Scanning S3 buckets and security configurations..." />;
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchBuckets} />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl shadow-sm">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Database className="h-6 w-6 text-amber-400" />
            S3 Bucket Inventory
          </h1>
          <p className="text-xs text-slate-400">
            Discovered buckets, default encryption, Public Access Block, and publicity status
          </p>
        </div>

        <button
          onClick={fetchBuckets}
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
            placeholder="Search bucket name..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500"
          />
        </div>

        <div>
          <select
            value={publicFilter}
            onChange={(e) => setPublicFilter(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
          >
            <option value="all">All Access Types</option>
            <option value="private">Private Only</option>
            <option value="public">Public / Exposed Only</option>
          </select>
        </div>

        <div>
          <select
            value={encryptionFilter}
            onChange={(e) => setEncryptionFilter(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
          >
            <option value="all">All Encryption States</option>
            <option value="encrypted">Encrypted Only</option>
            <option value="unencrypted">Unencrypted Only</option>
          </select>
        </div>
      </div>

      {/* Table */}
      {filteredBuckets.length > 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Bucket Name</th>
                  <th className="py-3 px-4">Region</th>
                  <th className="py-3 px-4">Public Status</th>
                  <th className="py-3 px-4">Default Encryption</th>
                  <th className="py-3 px-4">Public Access Block</th>
                  <th className="py-3 px-4">Versioning</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {filteredBuckets.map((bucket) => {
                  const pab = bucket.public_access_block;
                  const pabComplete =
                    pab &&
                    pab.block_public_acls &&
                    pab.ignore_public_acls &&
                    pab.block_public_policy &&
                    pab.restrict_public_buckets;

                  return (
                    <tr key={bucket.name} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 font-mono font-semibold text-amber-400">
                        {bucket.name}
                      </td>
                      <td className="py-3 px-4 text-slate-300">{bucket.region}</td>
                      <td className="py-3 px-4">
                        {bucket.is_public ? (
                          <span className="inline-flex items-center gap-1 bg-rose-950 text-rose-400 px-2.5 py-0.5 rounded-full text-[10px] font-bold border border-rose-800">
                            <Unlock className="h-3 w-3" />
                            PUBLIC
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 bg-emerald-950 text-emerald-400 px-2.5 py-0.5 rounded-full text-[10px] font-bold border border-emerald-800">
                            <Lock className="h-3 w-3" />
                            PRIVATE
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {bucket.encryption_enabled ? (
                          <span className="inline-flex items-center gap-1.5 text-emerald-400">
                            <Check className="h-4 w-4" />
                            <span>{bucket.encryption_algorithm || 'AES-256'}</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-rose-400">
                            <X className="h-4 w-4" />
                            <span>Disabled</span>
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {pabComplete ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400">
                            <ShieldCheck className="h-4 w-4" />
                            <span>Full (4/4)</span>
                          </span>
                        ) : pab ? (
                          <span className="inline-flex items-center gap-1 text-amber-400">
                            <ShieldAlert className="h-4 w-4" />
                            <span>Partial</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-rose-400">
                            <X className="h-4 w-4" />
                            <span>None</span>
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`text-[11px] font-medium ${
                            bucket.versioning === 'Enabled'
                              ? 'text-emerald-400'
                              : 'text-slate-500'
                          }`}
                        >
                          {bucket.versioning || 'Disabled'}
                        </span>
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
          icon={Database}
          title="No S3 Buckets Found"
          description={
            buckets.length === 0
              ? 'No S3 buckets were found in your AWS account. Run a full scan to refresh inventory.'
              : 'No buckets match the current filters.'
          }
        />
      )}
    </div>
  );
};

export default S3Inventory;

