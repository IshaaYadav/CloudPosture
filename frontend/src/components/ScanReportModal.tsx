import React from 'react';
import { X, ShieldCheck, Database, Server } from 'lucide-react';
import type { ScanReport } from '../types';
import StatusBadge from './StatusBadge';
import SeverityBadge from './SeverityBadge';

interface ScanReportModalProps {
  report: ScanReport | null;
  isOpen: boolean;
  onClose: () => void;
}

export const ScanReportModal: React.FC<ScanReportModalProps> = ({ report, isOpen, onClose }) => {
  if (!isOpen || !report) return null;

  const score = report.summary?.score ?? null;
  const scoreDisplay = report.summary?.score_display ?? (score !== null ? `${score}%` : 'N/A');

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl text-slate-100">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-800">
          <div>
            <h2 className="text-xl font-bold flex items-center gap-2">
              <ShieldCheck className="h-6 w-6 text-emerald-400" />
              Scan Audit Report
            </h2>
            <p className="text-xs text-slate-400 mt-1">ID: {report.scan_id}</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Metadata Card */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
            <div>
              <span className="text-xs text-slate-400">Account ID</span>
              <p className="font-semibold text-sm">{report.account_id || 'N/A'}</p>
            </div>
            <div>
              <span className="text-xs text-slate-400">Timestamp</span>
              <p className="font-semibold text-sm">{new Date(report.timestamp).toLocaleString()}</p>
            </div>
            <div>
              <span className="text-xs text-slate-400">Posture Score</span>
              <p className={`font-bold text-sm ${score && score >= 80 ? 'text-emerald-400' : score && score >= 50 ? 'text-amber-400' : 'text-rose-400'}`}>
                {scoreDisplay}
              </p>
            </div>
            <div>
              <span className="text-xs text-slate-400">S3 Storage Key</span>
              <p className="font-mono text-xs truncate text-cyan-400" title={report.storage?.key || report.storage_key || ''}>
                {report.storage?.key || report.storage_key || 'Stored in S3'}
              </p>
            </div>
          </div>

          {/* Resources Summary */}
          <div className="grid grid-cols-3 gap-4">
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-800 flex items-center gap-3">
              <Server className="h-5 w-5 text-indigo-400" />
              <div>
                <p className="text-xs text-slate-400">EC2 Instances</p>
                <p className="text-lg font-bold">{report.instances?.length ?? 0}</p>
              </div>
            </div>
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-800 flex items-center gap-3">
              <Database className="h-5 w-5 text-amber-400" />
              <div>
                <p className="text-xs text-slate-400">S3 Buckets</p>
                <p className="text-lg font-bold">{report.buckets?.length ?? 0}</p>
              </div>
            </div>
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-800 flex items-center gap-3">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
              <div>
                <p className="text-xs text-slate-400">Security Checks</p>
                <p className="text-lg font-bold">{report.check_results?.length ?? 0}</p>
              </div>
            </div>
          </div>

          {/* Checks List */}
          <div>
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
              Security Benchmark Evaluations ({report.check_results?.length ?? 0})
            </h3>
            <div className="space-y-3">
              {report.check_results?.map((check) => (
                <div key={check.check_id} className="p-4 rounded-lg bg-slate-950/40 border border-slate-800">
                  <div className="flex items-center justify-between gap-4 mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-indigo-400">{check.check_id}</span>
                      <span className="font-medium text-sm text-slate-200">{check.check_name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={check.severity} />
                      <StatusBadge status={check.status} />
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 mb-2">{check.description}</p>
                  {check.remediation && (
                    <div className="mt-2 text-xs bg-slate-900 p-2.5 rounded border border-slate-800/80 text-slate-300">
                      <strong className="text-amber-400">Remediation: </strong>
                      {check.remediation}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium rounded-lg transition"
          >
            Close Report
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScanReportModal;

