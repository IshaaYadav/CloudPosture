import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Server,
  Database,
  RefreshCw,
  Play,
  CheckCircle2,
  HardDrive,
  Cloud,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import toast from 'react-hot-toast';
import api from '../services/api';
import type { AWSStatus, ScanReport, ScanSummary } from '../types';
import StatCard from '../components/StatCard';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';
import LoadingSpinner from '../components/LoadingSpinner';

const COLORS = {
  PASS: '#10B981',
  FAIL: '#EF4444',
  ERROR: '#F59E0B',
};

export const Dashboard: React.FC = () => {
  const [awsStatus, setAwsStatus] = useState<AWSStatus | null>(null);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [latestReport, setLatestReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [scanning, setScanning] = useState<boolean>(false);
  const [verifyingStorage, setVerifyingStorage] = useState<boolean>(false);
  const [verifyingAws, setVerifyingAws] = useState<boolean>(false);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const [statusRes, summaryRes] = await Promise.allSettled([
        api.getAWSStatus(),
        api.getSummary(),
      ]);

      if (statusRes.status === 'fulfilled') {
        setAwsStatus(statusRes.value);
      }
      if (summaryRes.status === 'fulfilled') {
        setSummary(summaryRes.value);
      }

      // Try fetching latest full report for charts & recent findings
      try {
        const report = await api.getLatestScan();
        setLatestReport(report);
      } catch {
        // No scans run yet is normal on initial launch
      }
    } catch (err: any) {
      toast.error('Failed to load dashboard data: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const handleVerifyAws = async () => {
    try {
      setVerifyingAws(true);
      const res = await api.verifyAWS();
      setAwsStatus(res);
      if (res.connected) {
        toast.success(`AWS Connected: Account ${res.account_id}`);
      } else {
        toast.error('AWS verification failed: No valid credentials');
      }
    } catch (err: any) {
      toast.error(err.message || 'AWS Verification failed');
    } finally {
      setVerifyingAws(false);
    }
  };

  const handleVerifyStorage = async () => {
    try {
      setVerifyingStorage(true);
      const res = await api.verifyStorage();
      if (res.success || res.status === 'PASSED') {
        toast.success(`S3 Bucket '${res.bucket || res.bucket_name}' verified successfully!`);
      } else {
        toast.error(`Storage Verification Failed: ${res.message}`);
      }
    } catch (err: any) {
      toast.error(err.message || 'Storage Verification failed');
    } finally {
      setVerifyingStorage(false);
    }
  };

  const handleRunScan = async () => {
    try {
      setScanning(true);
      toast.loading('Starting full cloud posture scan...', { id: 'scan-toast' });
      const report = await api.runScan();
      setLatestReport(report);
      if (report.summary) {
        setSummary(report.summary);
      }
      toast.success(
        `Scan complete! Posture score: ${report.summary?.score_display || 'N/A'}. Saved to S3.`,
        { id: 'scan-toast' }
      );
      fetchDashboardData();
    } catch (err: any) {
      toast.error(`Scan execution failed: ${err.message}`, { id: 'scan-toast' });
    } finally {
      setScanning(false);
    }
  };

  if (loading && !summary && !awsStatus) {
    return <LoadingSpinner text="Connecting to AWS and loading security posture..." />;
  }

  // Chart data
  const passCount = summary?.passed ?? 0;
  const failCount = summary?.failed ?? 0;
  const errorCount = summary?.errors ?? 0;

  const statusPieData = [
    { name: 'Passed', value: passCount, color: COLORS.PASS },
    { name: 'Failed', value: failCount, color: COLORS.FAIL },
    { name: 'Error', value: errorCount, color: COLORS.ERROR },
  ].filter((item) => item.value > 0);

  // Severity distribution from latest report findings
  const severityCounts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };

  latestReport?.check_results?.forEach((c) => {
    if (c.status === 'FAIL' && severityCounts[c.severity] !== undefined) {
      severityCounts[c.severity]++;
    }
  });

  const severityBarData = Object.keys(severityCounts).map((sev) => ({
    name: sev,
    count: severityCounts[sev],
  }));

  const score = summary?.score ?? null;
  const scoreDisplay = summary?.score_display ?? (score !== null ? `${score}%` : 'N/A');

  return (
    <div className="space-y-6">
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl shadow-sm">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
            Cloud Posture Overview
          </h1>
          <p className="text-xs text-slate-400">
            Real-time CIS AWS Foundations Benchmark compliance & inventory
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleVerifyAws}
            disabled={verifyingAws}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 flex items-center gap-1.5 transition disabled:opacity-50"
          >
            <Cloud className={`h-4 w-4 ${verifyingAws ? 'animate-pulse text-indigo-400' : ''}`} />
            {verifyingAws ? 'Verifying AWS...' : 'Verify AWS'}
          </button>

          <button
            onClick={handleVerifyStorage}
            disabled={verifyingStorage}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 flex items-center gap-1.5 transition disabled:opacity-50"
          >
            <HardDrive className={`h-4 w-4 ${verifyingStorage ? 'animate-pulse text-amber-400' : ''}`} />
            {verifyingStorage ? 'Testing S3...' : 'Test S3 Storage'}
          </button>

          <button
            onClick={fetchDashboardData}
            disabled={loading}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition"
            title="Refresh Dashboard"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>

          <button
            onClick={handleRunScan}
            disabled={scanning}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-emerald-900/30 flex items-center gap-2 transition disabled:opacity-50"
          >
            <Play className={`h-4 w-4 fill-white ${scanning ? 'animate-spin' : ''}`} />
            {scanning ? 'Executing Scan...' : 'Run Full Scan'}
          </button>
        </div>
      </div>

      {/* AWS Connection & Account Summary Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Cloud className="h-4 w-4 text-indigo-400" />
            AWS Account Context
          </span>
          <span
            className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-0.5 rounded-full ${
              awsStatus?.connected
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                : 'bg-rose-950 text-rose-400 border border-rose-800'
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                awsStatus?.connected ? 'bg-emerald-400' : 'bg-rose-400'
              }`}
            />
            {awsStatus?.connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
          <div>
            <span className="text-xs text-slate-400">Account ID</span>
            <p className="font-mono font-semibold text-slate-200 mt-0.5">
              {awsStatus?.account_id || 'Not configured'}
            </p>
          </div>
          <div>
            <span className="text-xs text-slate-400">Identity ARN</span>
            <p className="font-mono text-xs text-slate-300 mt-0.5 truncate" title={awsStatus?.arn}>
              {awsStatus?.arn || 'N/A'}
            </p>
          </div>
          <div>
            <span className="text-xs text-slate-400">Configured Region</span>
            <p className="font-semibold text-slate-200 mt-0.5">
              {awsStatus?.region || 'ap-southeast-2'}
            </p>
          </div>
          <div>
            <span className="text-xs text-slate-400">Last Verified</span>
            <p className="text-xs text-slate-300 mt-0.5">
              {awsStatus?.last_verified
                ? new Date(awsStatus.last_verified).toLocaleTimeString()
                : 'Never'}
            </p>
          </div>
        </div>
      </div>

      {/* Stats Cards Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard
          title="EC2 Instances"
          value={summary?.total_instances ?? 0}
          icon={Server}
          color="indigo"
        />
        <StatCard
          title="S3 Buckets"
          value={summary?.total_buckets ?? 0}
          icon={Database}
          color="amber"
        />
        <StatCard
          title="Checks Passed"
          value={summary?.passed ?? 0}
          icon={CheckCircle2}
          color="emerald"
        />
        <StatCard
          title="Checks Failed"
          value={summary?.failed ?? 0}
          icon={ShieldAlert}
          color="rose"
        />
        <StatCard
          title="Checks Error"
          value={summary?.errors ?? 0}
          icon={AlertTriangle}
          color="amber"
        />
      </div>

      {/* Posture Score & Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Posture Score Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col items-center justify-center text-center shadow-sm">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-4">
            Security Posture Score
          </span>

          <div className="relative flex items-center justify-center my-2">
            <div
              className={`w-36 h-36 rounded-full border-8 flex flex-col items-center justify-center shadow-inner ${
                score !== null && score >= 80
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
                  : score !== null && score >= 50
                  ? 'border-amber-500 text-amber-400 bg-amber-950/20'
                  : score !== null
                  ? 'border-rose-500 text-rose-400 bg-rose-950/20'
                  : 'border-slate-700 text-slate-400 bg-slate-800/40'
              }`}
            >
              <span className="text-3xl font-extrabold font-mono tracking-tight">
                {scoreDisplay}
              </span>
              <span className="text-[10px] text-slate-400 uppercase tracking-widest mt-0.5">
                {score !== null && score >= 80
                  ? 'Excellent'
                  : score !== null && score >= 50
                  ? 'Moderate'
                  : score !== null
                  ? 'At Risk'
                  : 'Uncalculated'}
              </span>
            </div>
          </div>

          <p className="text-xs text-slate-400 mt-4 max-w-xs leading-relaxed">
            Formula: PASS / (PASS + FAIL) × 100. Error results are excluded from the score denominator.
          </p>

          {summary?.storage_status && (
            <div className="mt-4 pt-4 border-t border-slate-800/80 w-full flex items-center justify-center gap-2 text-xs text-slate-400">
              <HardDrive className="h-3.5 w-3.5 text-cyan-400" />
              S3 Storage:{' '}
              <span className="font-semibold text-slate-200 capitalize">
                {summary.storage_status}
              </span>
            </div>
          )}
        </div>

        {/* Check Status Distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 block">
            Compliance Evaluation
          </span>
          {statusPieData.length > 0 ? (
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={statusPieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={70}
                    innerRadius={45}
                    paddingAngle={4}
                  >
                    {statusPieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                  />
                  <Legend verticalAlign="bottom" wrapperStyle={{ fontSize: '12px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-56 flex items-center justify-center text-xs text-slate-500">
              No evaluation data yet. Click &quot;Run Full Scan&quot;.
            </div>
          )}
        </div>

        {/* Failed Findings by Severity */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 block">
            Violations by Severity
          </span>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityBarData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis allowDecimals={false} stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                />
                <Bar dataKey="count" fill="#EF4444" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Benchmark Findings Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-sm overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-indigo-400" />
            CIS-Inspired Security Findings ({latestReport?.check_results?.length ?? 0})
          </h2>
          <span className="text-xs text-slate-400">
            {latestReport?.timestamp ? new Date(latestReport.timestamp).toLocaleString() : ''}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Check ID</th>
                <th className="py-3 px-4">Benchmark Name</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Affected Resources</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-200">
              {latestReport?.check_results && latestReport.check_results.length > 0 ? (
                latestReport.check_results.map((check) => (
                  <tr key={check.check_id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono font-semibold text-indigo-400">
                      {check.check_id}
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-200">
                      <div>{check.check_name}</div>
                      <div className="text-[11px] text-slate-400 mt-0.5 max-w-md truncate">
                        {check.description}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{check.category}</td>
                    <td className="py-3 px-4">
                      <SeverityBadge severity={check.severity} />
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={check.status} />
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">
                      {check.affected_resources?.length > 0
                        ? `${check.affected_resources.length} resource(s)`
                        : 'None'}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No scan results available. Click &quot;Run Full Scan&quot; to evaluate posture.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

