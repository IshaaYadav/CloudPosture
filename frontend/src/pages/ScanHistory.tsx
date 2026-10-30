import React, { useEffect, useState } from 'react';
import { History, Eye, RefreshCw, HardDrive, CheckCircle2, ShieldAlert, AlertTriangle } from 'lucide-react';
import toast from 'react-hot-toast';
import api from '../services/api';
import type { ScanHistoryItem, ScanReport } from '../types';
import ScanReportModal from '../components/ScanReportModal';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';

export const ScanHistory: React.FC = () => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedReport, setSelectedReport] = useState<ScanReport | null>(null);
  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [loadingReport, setLoadingReport] = useState<boolean>(false);

  const fetchHistory = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getScanHistory();
      setHistory(data);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve scan history from S3');
      toast.error('Failed to load scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleOpenScan = async (scanId: string) => {
    try {
      setLoadingReport(true);
      toast.loading('Fetching scan report from S3...', { id: 's3-fetch' });
      const report = await api.getScanById(scanId);
      setSelectedReport(report);
      setModalOpen(true);
      toast.dismiss('s3-fetch');
    } catch (err: any) {
      toast.error(`Could not load report from S3: ${err.message}`, { id: 's3-fetch' });
    } finally {
      setLoadingReport(false);
    }
  };

  const handleOpenLatest = async () => {
    try {
      setLoadingReport(true);
      toast.loading('Fetching latest scan report from S3...', { id: 's3-fetch' });
      const report = await api.getLatestScan();
      setSelectedReport(report);
      setModalOpen(true);
      toast.dismiss('s3-fetch');
    } catch (err: any) {
      toast.error(`Could not load latest report: ${err.message}`, { id: 's3-fetch' });
    } finally {
      setLoadingReport(false);
    }
  };

  if (loading && history.length === 0) {
    return <LoadingSpinner text="Retrieving historical scan reports from Amazon S3..." />;
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchHistory} />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl shadow-sm">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <History className="h-6 w-6 text-cyan-400" />
            Audit Scan History
          </h1>
          <p className="text-xs text-slate-400">
            Historical security posture assessments retrieved directly from your AWS S3 bucket
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleOpenLatest}
            disabled={loadingReport}
            className="px-3 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 transition disabled:opacity-50"
          >
            <Eye className="h-3.5 w-3.5" />
            View Latest Report
          </button>

          <button
            onClick={fetchHistory}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition"
            title="Refresh History"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* History Table */}
      {history.length > 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Scan ID</th>
                  <th className="py-3 px-4">Date & Time</th>
                  <th className="py-3 px-4">Account ID</th>
                  <th className="py-3 px-4">Resources</th>
                  <th className="py-3 px-4">Evaluations (P / F / E)</th>
                  <th className="py-3 px-4">Posture Score</th>
                  <th className="py-3 px-4">S3 Object Key</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {history.map((item) => {
                  const score = item.score;
                  return (
                    <tr key={item.scan_id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 font-mono font-semibold text-indigo-400">
                        {item.scan_id.substring(0, 13)}...
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {new Date(item.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">{item.account_id}</td>
                      <td className="py-3 px-4 font-medium">{item.total_resources}</td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2 font-mono text-[11px]">
                          <span className="text-emerald-400 flex items-center gap-0.5">
                            <CheckCircle2 className="h-3 w-3" />
                            {item.passed}
                          </span>
                          <span className="text-slate-500">/</span>
                          <span className="text-rose-400 flex items-center gap-0.5">
                            <ShieldAlert className="h-3 w-3" />
                            {item.failed}
                          </span>
                          <span className="text-slate-500">/</span>
                          <span className="text-amber-400 flex items-center gap-0.5">
                            <AlertTriangle className="h-3 w-3" />
                            {item.errors}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`font-mono font-bold text-xs ${
                            score !== null && score >= 80
                              ? 'text-emerald-400'
                              : score !== null && score >= 50
                              ? 'text-amber-400'
                              : score !== null
                              ? 'text-rose-400'
                              : 'text-slate-500'
                          }`}
                        >
                          {item.score_display || (score !== null ? `${score}%` : 'N/A')}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className="font-mono text-[10px] text-cyan-400 truncate max-w-xs block"
                          title={item.s3_key || item.storage_key}
                        >
                          {item.s3_key || item.storage_key || 'Stored in S3'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleOpenScan(item.scan_id)}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded border border-slate-700 flex items-center gap-1 ml-auto transition"
                        >
                          <Eye className="h-3 w-3" />
                          View
                        </button>
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
          icon={HardDrive}
          title="No Historical Scans Found"
          description="Every completed scan report is automatically uploaded to your S3 bucket. Run your first full scan from the dashboard to create an audit history."
        />
      )}

      {/* Full Scan Report Modal */}
      <ScanReportModal
        report={selectedReport}
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
      />
    </div>
  );
};

export default ScanHistory;

