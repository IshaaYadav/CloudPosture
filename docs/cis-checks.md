# CIS AWS Foundations Benchmark - Inspired Security Checks

## Overview

Cloud Posture Scanner implements **eight security checks** inspired by the [CIS Amazon Web Services Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services). These checks evaluate your AWS account's security posture against common best practices.

> **Disclaimer**: These checks are *inspired by* the CIS AWS Foundations Benchmark but do not constitute a formal CIS certification or complete compliance assessment. For official CIS compliance, use AWS Security Hub with the CIS Benchmark standard enabled.

## Check Details

### CHECK 1: S3 Public Access (CPS-S3-001)

| Property | Value |
|----------|-------|
| **ID** | CPS-S3-001 |
| **Name** | S3 Bucket Public Access |
| **Category** | Storage |
| **Severity** | CRITICAL |
| **CIS Reference** | CIS AWS 2.1.1 - Ensure S3 Bucket Policy is set to deny HTTP requests |

**What it checks:**
- S3 bucket policy status (IsPublic)
- Bucket ACL grants to AllUsers or AuthenticatedUsers
- Public Access Block configuration

**Evidence provided:**
- List of public buckets with reasons
- Policy status details
- ACL grant details

**Remediation:**
- Enable S3 Block Public Access at the bucket level
- Review and restrict bucket policies
- Remove public ACL grants

---

### CHECK 2: S3 Default Encryption (CPS-S3-002)

| Property | Value |
|----------|-------|
| **ID** | CPS-S3-002 |
| **Name** | S3 Bucket Default Encryption |
| **Category** | Storage |
| **Severity** | HIGH |
| **CIS Reference** | CIS AWS 2.1.1 - Ensure S3 default encryption is enabled |

**What it checks:**
- Default server-side encryption configuration
- Encryption algorithm (AES256 / aws:kms)

**Evidence provided:**
- Encryption status per bucket
- Encryption algorithm used

**Remediation:**
- Enable SSE-S3 (AES256) or SSE-KMS default encryption
- Apply encryption to all buckets

---

### CHECK 3: Root Account MFA (CPS-IAM-001)

| Property | Value |
|----------|-------|
| **ID** | CPS-IAM-001 |
| **Name** | Root Account MFA |
| **Category** | IAM |
| **Severity** | CRITICAL |
| **CIS Reference** | CIS AWS 1.5 - Ensure MFA is enabled for the root user account |

**What it checks:**
- IAM Account Summary `AccountMFAEnabled` flag
- Credential report for root account MFA status

**Evidence provided:**
- MFA enabled/disabled status
- Account summary details

**Remediation:**
- Enable MFA for the root AWS account
- Use a hardware MFA device for the root account (recommended)
- At minimum, enable virtual MFA

> **Note**: This check returns ERROR if IAM permissions are insufficient. It will never return PASS when data is unavailable.

---

### CHECK 4: CloudTrail Enabled (CPS-LOG-001)

| Property | Value |
|----------|-------|
| **ID** | CPS-LOG-001 |
| **Name** | CloudTrail Logging |
| **Category** | Logging |
| **Severity** | HIGH |
| **CIS Reference** | CIS AWS 3.1 - Ensure CloudTrail is enabled in all regions |

**What it checks:**
- At least one CloudTrail trail exists
- Trail is configured as multi-region
- Trail is actively logging

**Evidence provided:**
- List of trails with configuration
- Multi-region status
- Logging status per trail

**Remediation:**
- Create a CloudTrail trail in your primary region
- Enable multi-region logging
- Ensure the trail is actively logging
- Configure an S3 bucket for log storage

> **Note**: This application does NOT create trails automatically.

---

### CHECK 5: SSH Exposure (CPS-NET-001)

| Property | Value |
|----------|-------|
| **ID** | CPS-NET-001 |
| **Name** | SSH Public Exposure |
| **Category** | Network |
| **Severity** | HIGH |
| **CIS Reference** | CIS AWS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 |

**What it checks:**
- Security group inbound rules
- TCP port 22 open to 0.0.0.0/0 (IPv4 any)
- TCP port 22 open to ::/0 (IPv6 any)

**Evidence provided:**
- List of affected security groups
- Security group IDs and names
- VPC association
- Offending rule details

**Remediation:**
- Restrict SSH access to specific IP ranges
- Use AWS Systems Manager Session Manager instead of direct SSH
- Implement bastion hosts with restricted access

---

### CHECK 6: RDP Exposure (CPS-NET-002)

| Property | Value |
|----------|-------|
| **ID** | CPS-NET-002 |
| **Name** | RDP Public Exposure |
| **Category** | Network |
| **Severity** | HIGH |
| **CIS Reference** | CIS AWS 5.3 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 |

**What it checks:**
- Security group inbound rules
- TCP port 3389 open to 0.0.0.0/0 (IPv4 any)
- TCP port 3389 open to ::/0 (IPv6 any)

**Evidence provided:**
- List of affected security groups
- Offending rule details

**Remediation:**
- Restrict RDP access to specific IP ranges
- Use VPN or AWS Systems Manager for remote access
- Disable RDP if not needed

---

### CHECK 7: S3 Public Access Block (CPS-S3-003)

| Property | Value |
|----------|-------|
| **ID** | CPS-S3-003 |
| **Name** | S3 Public Access Block Configuration |
| **Category** | Storage |
| **Severity** | MEDIUM |
| **CIS Reference** | CIS AWS 2.1.5 - Ensure S3 bucket access is restricted |

**What it checks all four Public Access Block settings:**
- `BlockPublicAcls`
- `IgnorePublicAcls`
- `BlockPublicPolicy`
- `RestrictPublicBuckets`

**Evidence provided:**
- Per-bucket Public Access Block configuration
- Which settings are missing or disabled

**Remediation:**
- Enable all four Public Access Block settings on every bucket
- Consider enabling account-level S3 Block Public Access

---

### CHECK 8: EC2 Public Exposure (CPS-EC2-001)

| Property | Value |
|----------|-------|
| **ID** | CPS-EC2-001 |
| **Name** | EC2 Public Instance Exposure |
| **Category** | Compute |
| **Severity** | MEDIUM |
| **CIS Reference** | General best practice - Minimize public attack surface |

**What it checks:**
- Running EC2 instances with public IP addresses
- Associated security groups with exposed management ports (22, 3389, 443, 80)
- Combined risk: public IP + open management ports

**Evidence provided:**
- Instance IDs with public IPs
- Associated security groups
- Exposed ports on those security groups

**Remediation:**
- Remove unnecessary public IP assignments
- Use private subnets with NAT Gateway for internet access
- Restrict security group rules to specific IP ranges
- Use AWS Systems Manager for instance management

> **Note**: A public IP address alone does not constitute a FAIL. The check identifies instances that have both a public IP AND security groups with exposed management ports.

---

## Scoring

The security posture score is calculated as:

$$\text{Score} = \frac{\text{PASS count}}{\text{PASS count} + \text{FAIL count}} \times 100$$

- **ERROR** checks are excluded from the score calculation
- If no checks were successfully evaluated, the score displays as **N/A**
- The number of ERROR checks is displayed separately

## Status Definitions

| Status | Meaning |
|--------|---------|
| **PASS** | The check was evaluated successfully and the configuration meets the security requirement |
| **FAIL** | The check was evaluated successfully and a security violation was identified |
| **ERROR** | The check could not be evaluated (e.g., insufficient permissions, API error) |

## Limitations

- These checks cover a subset of the full CIS AWS Foundations Benchmark
- Some checks require specific IAM permissions that may not be available
- Results depend on the permissions granted to the scanning identity
- Account-level configurations may require elevated permissions
- This tool does not modify any AWS resources or configurations

