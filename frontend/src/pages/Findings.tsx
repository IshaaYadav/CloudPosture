import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Search,
  ChevronDown,
  ChevronUp,
  Wrench,
  FileText,
  RefreshCw,
} from 'lucide-react';
import toast from 'react-hot-toast';
import api from '../services/api';
import type { CheckResult } from '../types';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';

export const Findings: React.FC = () => {
  const [findings, setFindings] = useState<CheckResult[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const [expandedCheckId, setExpandedCheckId] = useState<string | null>(null);

  const fetchFindings = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getCISResults();
      setFindings(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load CIS findings');
      toast.error('Failed to load CIS benchmark results');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, []);

  const categories = Array.from(new Set(findings.map((f) => f.category))).filter(Boolean);

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.check_id.toLowerCase().includes(search.toLowerCase()) ||
      f.check_name.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase());

    const matchesStatus = statusFilter === 'all' || f.status.toUpperCase() === statusFilter.toUpperCase();
    const matchesSeverity = severityFilter === 'all' || f.severity.toUpperCase() === severityFilter.toUpperCase();
    const matchesCategory = categoryFilter === 'all' || f.category.toLowerCase() === categoryFilter.toLowerCase();

    return matchesSearch && matchesStatus && matchesSeverity && matchesCategory;
  });

  const toggleExpand = (checkId: string) => {
    setExpandedCheckId((prev) => (prev === checkId ? null : checkId));
  };

  if (loading) {
    return <LoadingSpinner text="Evaluating CIS AWS Foundations Benchmark findings..." />;
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchFindings} />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl shadow-sm">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-emerald-400" />
            CIS AWS Security Findings
          </h1>
          <p className="text-xs text-slate-400">
            Automated configuration assessments based on CIS AWS Foundations Benchmark
          </p>
        </div>

        <button
          onClick={fetchFindings}
          className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 flex items-center gap-2 transition"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh Findings
        </button>
      </div>

      {/* Filter Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search checks by ID or name..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
          />
        </div>

        <div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All Outcomes</option>
            <option value="PASS">PASS Only</option>
            <option value="FAIL">FAIL Only</option>
            <option value="ERROR">ERROR Only</option>
          </select>
        </div>

        <div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>

        <div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All Categories</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Findings Cards List */}
      {filteredFindings.length > 0 ? (
        <div className="space-y-4">
          {filteredFindings.map((check) => {
            const isExpanded = expandedCheckId === check.check_id;
            return (
              <div
                key={check.check_id}
                className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm transition hover:border-slate-700"
              >
                {/* Header row */}
                <div
                  onClick={() => toggleExpand(check.check_id)}
                  className="p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 cursor-pointer select-none"
                >
                  <div className="flex items-start sm:items-center gap-3">
                    <span className="font-mono text-xs font-bold text-indigo-400 bg-indigo-950/60 border border-indigo-800/80 px-2 py-1 rounded">
                      {check.check_id}
                    </span>
                    <div>
                      <h3 className="font-semibold text-sm text-slate-100">{check.check_name}</h3>
                      <p className="text-xs text-slate-400 mt-0.5 line-clamp-1">{check.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 self-end sm:self-auto">
                    <span className="text-[11px] text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                      {check.category}
                    </span>
                    <SeverityBadge severity={check.severity} />
                    <StatusBadge status={check.status} />
                    <button className="text-slate-400 hover:text-white p-1">
                      {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="border-t border-slate-800/80 p-5 bg-slate-950/40 space-y-4">
                    {/* Description */}
                    <div>
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1 flex items-center gap-1.5">
                        <FileText className="h-3.5 w-3.5 text-indigo-400" />
                        Benchmark Requirement
                      </h4>
                      <p className="text-xs text-slate-300 leading-relaxed">{check.description}</p>
                    </div>

                    {/* Affected Resources */}
                    {check.affected_resources && check.affected_resources.length > 0 && (
                      <div>
                        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">
                          Affected Resources ({check.affected_resources.length})
                        </h4>
                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {check.affected_resources.map((res, idx) => (
                            <span
                              key={idx}
                              className="font-mono text-[11px] bg-rose-950/50 text-rose-300 border border-rose-900/60 px-2 py-0.5 rounded"
                            >
                              {res}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Evidence Output */}
                    {check.evidence && check.evidence.length > 0 && (
                      <div>
                        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">
                          Audit Evidence & Findings
                        </h4>
                        <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-48">
                          {JSON.stringify(check.evidence, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Remediation Advice */}
                    {check.remediation && (
                      <div className="p-3 bg-amber-950/20 border border-amber-900/50 rounded-lg text-xs text-amber-200 flex items-start gap-2.5">
                        <Wrench className="h-4 w-4 text-amber-400 flex-shrink-0 mt-0.5" />
                        <div>
                          <strong className="text-amber-300 block mb-0.5">Remediation Steps:</strong>
                          <span>{check.remediation}</span>
                        </div>
                      </div>
                    )}

                    <div className="text-[10px] text-slate-500 pt-1">
                      Evaluated at: {new Date(check.timestamp).toUTCString()}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <EmptyState
          icon={ShieldAlert}
          title="No Matching Findings"
          description={
            findings.length === 0
              ? 'No security benchmark checks have been evaluated yet. Run a full scan from the dashboard.'
              : 'No findings match the current filter criteria.'
          }
        />
      )}
    </div>
  );
};

export default Findings;

