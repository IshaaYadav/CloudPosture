import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Dashboard from '../pages/Dashboard';

// Mock API module
vi.mock('../services/api', () => ({
  default: {
    getAWSStatus: vi.fn().mockResolvedValue({
      connected: true,
      account_id: '123456789012',
      arn: 'arn:aws:iam::123456789012:user/scanner',
      user_id: 'AIDA123',
      region: 'ap-southeast-2',
      last_verified: new Date().toISOString(),
    }),
    getSummary: vi.fn().mockResolvedValue({
      total_resources: 10,
      total_instances: 4,
      total_buckets: 6,
      total_checks: 8,
      passed: 6,
      failed: 2,
      errors: 0,
      score: 75.0,
      score_display: '75.0%',
    }),
    getLatestScan: vi.fn().mockResolvedValue({
      scan_id: 'test-scan-001',
      timestamp: new Date().toISOString(),
      account_id: '123456789012',
      region: 'ap-southeast-2',
      instances: [],
      buckets: [],
      check_results: [],
      summary: {
        total_resources: 10,
        total_instances: 4,
        total_buckets: 6,
        total_checks: 8,
        passed: 6,
        failed: 2,
        errors: 0,
        score: 75.0,
        score_display: '75.0%',
      },
      storage: {
        status: 'stored',
        bucket: 'test-bucket',
        key: 'cloud-posture-scanner/latest/latest_scan.json',
      },
    }),
  },
}));

describe('Dashboard Component', () => {
  it('renders dashboard title and action controls', async () => {
    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>
    );

    // Check title presence
    expect(await screen.findByText(/Cloud Posture Overview/i)).toBeInTheDocument();
    // Check buttons
    expect(screen.getByRole('button', { name: /Run Full Scan/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Verify AWS/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Test S3 Storage/i })).toBeInTheDocument();
  });
});

