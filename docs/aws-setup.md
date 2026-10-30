# AWS Account Setup Guide

## Complete Setup Process

### 1. AWS Account

If you don't have an AWS account:
1. Go to [AWS Sign Up](https://aws.amazon.com/free/)
2. Create a Free Tier account
3. Complete identity verification

> **⚠️ Warning**: Never use root credentials for this application. Create a dedicated IAM user.

### 2. Create a Dedicated IAM User

1. Sign in to the [IAM Console](https://console.aws.amazon.com/iam/)
2. Navigate to **Users** → **Create user**
3. User name: `cloud-posture-scanner`
4. Select **Attach policies directly**
5. Click **Create policy** → **JSON**
6. Paste the contents of `infrastructure/iam-policy.json`
   - **Important**: Replace `YOUR-REPORT-BUCKET-NAME` with your actual S3 bucket name
7. Name the policy: `CloudPostureScannerPolicy`
8. Attach the policy to the user
9. Create the user

### 3. Generate Access Keys

1. Open the IAM user `cloud-posture-scanner`
2. Go to **Security credentials** tab
3. Click **Create access key**
4. Select **Command Line Interface (CLI)**
5. Download the `.csv` file or copy the keys
6. **Store these keys securely** — you won't see the secret key again

### 4. Create the S3 Report Bucket

Follow the detailed instructions in `infrastructure/s3-setup.md`.

Quick summary:
1. Go to [S3 Console](https://s3.console.aws.amazon.com/s3/)
2. Create bucket with a unique name
3. Region: `ap-southeast-2` (Asia Pacific – Sydney, or your preferred region)
4. Block all public access: **Enabled**
5. Default encryption: **SSE-S3**
6. Versioning: **Disabled**

### 5. Install AWS CLI

#### Windows
Download and install from: https://aws.amazon.com/cli/

```powershell
# Verify installation
aws --version
```

#### macOS
```bash
brew install awscli
```

#### Linux
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

### 6. Configure AWS CLI Named Profile

```bash
aws configure --profile cloud-posture-scanner
```

Enter:
- **AWS Access Key ID**: Your access key
- **AWS Secret Access Key**: Your secret key
- **Default region name**: `ap-southeast-2`
- **Default output format**: `json`

### 7. Verify AWS Configuration

```bash
# Verify identity
aws sts get-caller-identity --profile cloud-posture-scanner

# Expected output:
# {
#     "UserId": "AIDAEXAMPLE",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/cloud-posture-scanner"
# }

# Verify S3 access
aws s3 ls --profile cloud-posture-scanner

# Verify specific bucket
aws s3 ls s3://YOUR-BUCKET-NAME --profile cloud-posture-scanner
```

### 8. Configure the Application

Copy the example environment file:
```bash
cp .env.example .env
```

Edit `.env`:
```env
AWS_PROFILE=cloud-posture-scanner
AWS_REGION=ap-southeast-2
POSTURE_RESULTS_BUCKET=your-actual-bucket-name
```

### 9. Start the Application

**Backend:**
```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### 10. Verify in the Dashboard

1. Open http://localhost:5173
2. Click **Verify AWS Connection** — should show green status with your account ID
3. Click **Test S3 Storage** — should show successful storage verification
4. Click **Run Full Scan** — should complete and show results

### 11. Verify S3 Report

After running a scan:
1. Go to [S3 Console](https://s3.console.aws.amazon.com/s3/)
2. Open your report bucket
3. Navigate to `cloud-posture-scanner/scans/YYYY/MM/DD/`
4. Verify the scan report JSON file exists
5. Check `cloud-posture-scanner/latest/latest_scan.json`

## AWS Free Tier Considerations

| Service | Free Tier Limit | This App Usage |
|---------|----------------|----------------|
| S3 Storage | 5 GB for 12 months | < 1 MB (scan reports) |
| S3 PUT Requests | 2,000/month | ~10/scan |
| S3 GET Requests | 20,000/month | ~20/scan |
| API Calls (EC2, IAM, etc.) | Mostly free | Minimal read-only calls |

> **Note**: After the 12-month Free Tier period, S3 Standard costs ~$0.025/GB/month. With scan reports averaging < 50 KB each, costs will be negligible.

## Troubleshooting

### "Unable to locate credentials"
- Verify AWS CLI is installed: `aws --version`
- Verify profile exists: `aws configure list --profile cloud-posture-scanner`
- Check `~/.aws/credentials` file

### "AccessDenied" errors
- Verify the IAM policy is attached to your user
- Verify the policy has the correct permissions
- Some API calls (like `iam:GetCredentialReport`) may require specific permissions
- Check CloudTrail for denied API calls

### "NoSuchBucket" error
- Verify the bucket name in `.env` matches your actual bucket
- Verify the bucket exists in the correct region

### Partial scan results
- Some regions may not be enabled in your account
- Some API calls may fail due to permission restrictions
- ERROR results indicate checks that couldn't be evaluated
- The scan continues even if individual checks fail

## Security Best Practices

1. **Never use root credentials** — always use an IAM user with limited permissions
2. **Rotate access keys** regularly
3. **Enable MFA** on all IAM users (and especially the root account)
4. **Review IAM policies** — the provided policy grants read-only access
5. **Monitor AWS costs** — set up billing alerts
6. **Don't commit `.env`** — it's in `.gitignore`
7. **Don't share access keys** — use IAM roles for team members

