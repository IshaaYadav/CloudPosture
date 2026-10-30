# S3 Bucket Setup for Cloud Posture Scanner

## Overview

Cloud Posture Scanner stores all scan reports in your own AWS S3 bucket. This guide walks you through creating and configuring the bucket properly.

> **Important**: The application will NEVER create a bucket automatically. You must create it manually.

## Prerequisites

- An AWS account
- AWS Management Console access
- AWS CLI installed and configured

## Step-by-Step S3 Bucket Setup

### 1. Create the S3 Bucket

1. Sign in to the [AWS S3 Console](https://s3.console.aws.amazon.com/s3/)
2. Click **Create bucket**
3. Configure:
   - **Bucket name**: Choose a unique name (e.g., `my-cloud-posture-reports-2024`)
   - **AWS Region**: `ap-southeast-2` (Asia Pacific - Sydney) or your preferred region
   - **Object Ownership**: ACLs disabled (recommended)

### 2. Block Public Access Settings

Under **Block Public Access settings for this bucket**:

- ✅ **Block all public access** — ENABLED
  - ✅ Block public access to buckets and objects granted through new access control lists (ACLs)
  - ✅ Block public access to buckets and objects granted through any access control lists (ACLs)
  - ✅ Block public and cross-account access to buckets and objects through any public bucket or access point policies
  - ✅ Block public access to buckets and objects granted through new public bucket or access point policies

> **Warning**: This bucket stores security scan reports. It should NEVER be publicly accessible.

### 3. Bucket Versioning

- **Bucket Versioning**: Disabled (default)
- You can enable versioning later if you want to preserve all report versions

### 4. Default Encryption

- **Encryption type**: Server-side encryption with Amazon S3 managed keys (SSE-S3)
- **Encryption key**: Amazon S3 managed key (SSE-S3)
- **Bucket Key**: Enabled (reduces KMS costs if you later switch to KMS)

### 5. Click "Create bucket"

### 6. Verify the Bucket

Using AWS CLI:

```bash
# List your buckets
aws s3 ls --profile cloud-posture-scanner

# Verify the specific bucket
aws s3 ls s3://YOUR-BUCKET-NAME --profile cloud-posture-scanner
```

## Storage Structure

The application uses this S3 structure:

```
YOUR-BUCKET-NAME/
└── cloud-posture-scanner/
    ├── scans/
    │   └── YYYY/
    │       └── MM/
    │           └── DD/
    │               └── scan_<scan-id>.json
    └── latest/
        └── latest_scan.json
```

## IAM Policy Configuration

After creating the bucket, update the IAM policy (`infrastructure/iam-policy.json`):

Replace `YOUR-REPORT-BUCKET-NAME` with your actual bucket name in these two statements:

```json
{
  "Sid": "S3ReportBucketReadWrite",
  "Resource": "arn:aws:s3:::YOUR-ACTUAL-BUCKET-NAME"
},
{
  "Sid": "S3ReportObjectsReadWrite",
  "Resource": "arn:aws:s3:::YOUR-ACTUAL-BUCKET-NAME/cloud-posture-scanner/*"
}
```

## Environment Configuration

Update your `.env` file:

```env
POSTURE_RESULTS_BUCKET=YOUR-ACTUAL-BUCKET-NAME
```

## Verification

After setup, verify from the application:

1. Start the backend: `uvicorn app.main:app --reload`
2. Navigate to `http://localhost:8000/docs`
3. Call `POST /storage/verify`
4. Verify the response shows success

Or from the dashboard:
1. Open `http://localhost:5173`
2. Click **Test S3 Storage**
3. Verify the green success notification

## Cost Considerations

- **S3 Standard storage**: First 5 GB free for 12 months (Free Tier)
- **PUT requests**: First 2,000 free per month (Free Tier)
- **GET requests**: First 20,000 free per month (Free Tier)
- Each scan report is typically < 50 KB
- Running a few scans per day will stay well within Free Tier limits

> **Note**: After the Free Tier period, S3 Standard storage costs approximately $0.025/GB/month. Scan reports are tiny, so costs will be negligible.

## Troubleshooting

### "Bucket not found" error
- Verify the bucket name in your `.env` matches exactly
- Verify the bucket is in the correct region

### "Access Denied" error
- Verify the IAM policy has the correct bucket ARN
- Verify the IAM policy is attached to your user/role
- Run: `aws s3 ls s3://YOUR-BUCKET-NAME --profile cloud-posture-scanner`

### "Encryption error"
- Ensure SSE-S3 is enabled as the default encryption
- The application uses `ServerSideEncryption='AES256'` for uploads

