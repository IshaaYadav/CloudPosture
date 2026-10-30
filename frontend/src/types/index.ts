export interface AWSStatus {
  connected: boolean;
  account_id: string;
  arn: string;
  user_id: string;
  region: string;
  last_verified: string;
}

export interface EC2Instance {
  instance_id: string;
  name: string;
  instance_type: string;
  region: string;
  state: string;
  public_ip: string | null;
  private_ip: string;
  vpc_id: string;
  subnet_id: string;
  security_group_ids: string[];
  security_group_names: string[];
}

export interface S3Bucket {
  name: string;
  region: string;
  encryption_enabled: boolean;
  encryption_algorithm: string | null;
  is_public: boolean;
  public_access_block: {
    block_public_acls: boolean;
    ignore_public_acls: boolean;
    block_public_policy: boolean;
    restrict_public_buckets: boolean;
  } | null;
  versioning: string;
  policy_status: string;
}

export interface CheckResult {
  check_id: string;
  check_name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  status: 'PASS' | 'FAIL' | 'ERROR';
  evidence: Record<string, any>[];
  remediation: string;
  timestamp: string;
  category: string;
  affected_resources: string[];
}

export interface ScanReport {
  scan_id: string;
  timestamp: string;
  account_id: string;
  region: string;
  instances: EC2Instance[];
  buckets: S3Bucket[];
  check_results: CheckResult[];
  summary: ScanSummary;
  storage: StorageInfo;
  storage_key?: string;
}

export interface ScanSummary {
  total_resources: number;
  total_instances: number;
  total_buckets: number;
  total_checks: number;
  passed: number;
  failed: number;
  errors: number;
  score: number | null;
  score_display: string;
  storage_status?: string;
}

export interface StorageInfo {
  status: string;
  bucket: string;
  key: string;
}

export interface ScanHistoryItem {
  scan_id: string;
  timestamp: string;
  account_id: string;
  total_resources: number;
  passed: number;
  failed: number;
  errors: number;
  score: number | null;
  score_display: string;
  s3_key: string;
  storage_key?: string;
}

export interface StorageVerification {
  success: boolean;
  bucket: string;
  bucket_name?: string;
  status?: string;
  message: string;
  details: Record<string, any>;
}

export interface HealthResponse {
  status: string;
  version: string;
  timestamp: string;
}
