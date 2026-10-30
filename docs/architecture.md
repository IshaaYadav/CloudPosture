# Architecture

## System Overview

Cloud Posture Scanner is a Cloud Security Posture Management (CSPM) tool that evaluates AWS account security configurations against CIS AWS Foundations Benchmark-inspired checks.

## Architecture Diagram

```mermaid
flowchart TB
    subgraph Frontend["React Frontend :5173"]
        UI["Dashboard UI"]
        API_CLIENT["Axios API Client"]
    end

    subgraph Backend["FastAPI Backend :8000"]
        ROUTES["API Routes"]
        SCANNER["Scan Engine"]
        CHECKS["Security Checks"]
        AWS_MOD["AWS Modules"]
        STORAGE["Report Storage"]
        STATE["In-Memory State"]
    end

    subgraph AWS["AWS Cloud"]
        STS["AWS STS"]
        EC2["EC2 API"]
        S3_API["S3 API"]
        IAM["IAM API"]
        CT["CloudTrail API"]
        S3_BUCKET["S3 Report Bucket"]
    end

    UI --> API_CLIENT
    API_CLIENT -->|"REST API"| ROUTES
    ROUTES --> SCANNER
    ROUTES --> STATE
    SCANNER --> AWS_MOD
    SCANNER --> CHECKS
    SCANNER --> STORAGE
    CHECKS --> AWS_MOD
    AWS_MOD -->|"boto3"| STS
    AWS_MOD -->|"boto3"| EC2
    AWS_MOD -->|"boto3"| S3_API
    AWS_MOD -->|"boto3"| IAM
    AWS_MOD -->|"boto3"| CT
    STORAGE -->|"boto3"| S3_BUCKET
    SCANNER --> STATE
```

## Data Flow Diagram

```mermaid
sequenceDiagram
    participant User
    participant Dashboard as React Dashboard
    participant API as FastAPI Backend
    participant Scanner as Scan Engine
    participant AWS as AWS APIs
    participant S3 as S3 Report Bucket

    User->>Dashboard: Click "Run Full Scan"
    Dashboard->>API: POST /scan
    API->>Scanner: run_full_scan()
    
    Scanner->>AWS: STS GetCallerIdentity
    AWS-->>Scanner: Account Identity
    
    Scanner->>AWS: EC2 DescribeRegions
    AWS-->>Scanner: Enabled Regions
    
    Scanner->>AWS: EC2 DescribeInstances (per region)
    AWS-->>Scanner: EC2 Instances
    
    Scanner->>AWS: S3 ListBuckets + Details
    AWS-->>Scanner: S3 Buckets
    
    Scanner->>AWS: IAM GetAccountSummary
    AWS-->>Scanner: Account Security Info
    
    Scanner->>AWS: CloudTrail DescribeTrails
    AWS-->>Scanner: Trail Configurations
    
    Note over Scanner: Execute 8 CIS Security Checks
    Note over Scanner: Calculate Posture Score
    Note over Scanner: Generate JSON Report
    
    Scanner->>S3: PutObject (scan report)
    S3-->>Scanner: Upload Confirmation
    
    Scanner->>S3: PutObject (latest_scan.json)
    S3-->>Scanner: Upload Confirmation
    
    Scanner-->>API: ScanReport
    API-->>Dashboard: JSON Response
    Dashboard-->>User: Display Results
```

## Component Architecture

### Backend Components

| Component | Responsibility |
|-----------|---------------|
| `app/aws/session.py` | AWS session management, credential handling |
| `app/aws/ec2.py` | EC2 instance and region discovery |
| `app/aws/s3.py` | S3 bucket discovery and configuration analysis |
| `app/aws/iam.py` | IAM account summary and credential reports |
| `app/aws/cloudtrail.py` | CloudTrail trail discovery and status |
| `app/aws/security_groups.py` | Security group analysis for port exposure |
| `app/checks/*.py` | Individual CIS-inspired security checks |
| `app/services/scanner.py` | Scan orchestration engine |
| `app/services/report_storage.py` | S3 report upload, retrieval, and management |
| `app/services/posture_score.py` | Security posture score calculation |
| `app/services/scan_state.py` | In-memory scan state management |
| `app/api/routes/*.py` | REST API endpoints |
| `app/schemas/*.py` | Pydantic data models |

### Frontend Components

| Component | Responsibility |
|-----------|---------------|
| `pages/Dashboard.tsx` | Overview with stats, charts, and actions |
| `pages/EC2Inventory.tsx` | Searchable EC2 instance table |
| `pages/S3Inventory.tsx` | Searchable S3 bucket table |
| `pages/Findings.tsx` | CIS security findings with filters |
| `pages/ScanHistory.tsx` | Historical scan reports from S3 |
| `layouts/DashboardLayout.tsx` | Sidebar navigation and layout |
| `services/api.ts` | Axios-based API client |
| `hooks/useApi.ts` | React hook for API state management |

## Security Architecture

- **No stored credentials**: Uses AWS CLI named profiles or standard credential chain
- **Least-privilege IAM**: Read-only access to AWS resources, write only to report bucket
- **No resource modification**: Application never creates, modifies, or deletes AWS resources
- **No data inspection**: Never downloads or reads actual S3 object contents
- **Encryption**: All reports stored with SSE-S3 encryption
- **CORS**: Restricted to configured frontend origins
- **No secrets in frontend**: All AWS operations happen server-side

## Deployment Model

The application runs entirely locally:
- Backend: Python/FastAPI on port 8000
- Frontend: React/Vite on port 5173
- Storage: AWS S3 (remote, managed by AWS)

No cloud infrastructure is provisioned. Only S3 is used for persistent storage.

