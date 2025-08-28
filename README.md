# AWS Security Monitor

Comprehensive AWS security monitoring system that provides real-time security group analysis and change detection across multiple AWS accounts.

## Features

- 🔍 **Multi-Account Monitoring**: Automatically discovers and monitors all AWS accounts from `~/.aws/credentials`
- 🚨 **Security Group Analysis**: Scans 100+ security groups with risk classification (Critical/Medium/Low)
- 📊 **Change Detection**: Tracks IAM user activities across EC2, S3, and RDS services
- 📧 **Automated Reporting**: Sends daily executive reports via AWS SES with CSV attachments
- ⚡ **Real-time Scanning**: Live security group scanning across multiple AWS regions

## Recent Updates

### CloudTrail Detection Fixed (2025-08-28)
- ✅ Fixed CloudTrail API parameter (`MaxItems` → `MaxResults`)
- ✅ Now detects 53+ changes vs 0 previously
- ✅ Includes DeleteSnapshot, CreateSnapshot, and other critical events
- ✅ Works with all IAM users (MoinuddinE, mdua, chandrak, vbutola, etc.)

### Expanded Event Coverage
- **EC2**: RunInstances, TerminateInstances, StartInstances, StopInstances, DeleteSnapshot, CreateSnapshot
- **S3**: CreateBucket, DeleteBucket, PutBucketPolicy, DeleteBucketPolicy
- **RDS**: StopDBInstance, StartDBInstance, DeleteDBInstance, CreateDBInstance

## Installation

1. **Copy the script to production server:**
   ```bash
   scp send-comprehensive-report.py root@server:~/aws-security-report/
   chmod +x ~/aws-security-report/send-comprehensive-report.py
   ```

2. **Install dependencies:**
   ```bash
   pip3 install boto3 --break-system-packages
   ```

3. **Setup cron for daily reports:**
   ```bash
   crontab -e
   # Add this line:
   0 9 * * * python3 /root/aws-security-report/send-comprehensive-report.py >> /var/log/executive-report.log 2>&1
   ```

## Configuration

### AWS Profiles
The system automatically discovers all profiles from `~/.aws/credentials`:
```ini
[personal]
aws_access_key_id = YOUR_KEY
aws_secret_access_key = YOUR_SECRET

[unified] 
aws_access_key_id = YOUR_KEY
aws_secret_access_key = YOUR_SECRET

[bamkom]
aws_access_key_id = YOUR_KEY
aws_secret_access_key = YOUR_SECRET
```

### Email Configuration
Update the email settings in `send-comprehensive-report.py`:
```python
SENDER_EMAIL = "no-reply@bamko.net"
RECIPIENT_EMAIL = "cmkhetwal@hotmail.com"
```

### Critical Instances (Optional)
Create `critical-instances.txt` to mark instances as critical:
```
i-0d9accba83df8dc59
i-0712c137f52ca12a0
i-08554b77d1ccefb6c
```

## Usage

### Manual Run
```bash
python3 send-comprehensive-report.py
```

### Expected Output
```
=== COMPREHENSIVE AWS SECURITY SCAN ===
✅ Discovered 3 AWS profiles: personal, unified, bamkom
✅ Security group scan complete: 108 internet-exposed groups found
   🔴 CRITICAL: 0
   🟡 MEDIUM: 17
   🟢 LOW: 91
✅ Comprehensive change detection complete: 53 changes found
   💾 EC2: 45 changes
   📦 S3: 5 changes
   🗄️ RDS: 3 changes
✅ COMPREHENSIVE SECURITY REPORT SENT SUCCESSFULLY!
```

## Risk Classification

- **🔴 CRITICAL**: Any port exposed to internet on instances listed in `critical-instances.txt`
- **🟡 MEDIUM**: Non-web ports (SSH, OpenVPN, MySQL, etc.) exposed to internet
- **🟢 LOW**: Only web ports (80/443) exposed to internet

## Report Contents

Daily reports include:
- Executive summary of all AWS changes in last 24 hours
- Complete security group analysis with risk breakdown
- IAM user activity tracking
- CSV attachment with detailed security group data
- Immediate action recommendations

## Files

- `send-comprehensive-report.py` - Main comprehensive monitoring script
- `email-config.txt` - Email configuration
- `critical-instances.txt` - Critical instance definitions (optional)
- `README.md` - This documentation

## Troubleshooting

### No Changes Detected
If no changes are detected, check:
1. CloudTrail is enabled in your AWS regions
2. AWS credentials have CloudTrail permissions
3. Time windows (events may have 15-30 min delay)

### Email Delivery Issues
1. Verify SES identity is verified: `no-reply@bamko.net`
2. Check SES region configuration (us-east-1)
3. Ensure unified profile has SES permissions

## Security

- Only detects IAM user activities (excludes service roles)
- Filters out AWS internal and system events
- Uses read-only AWS APIs
- No secrets stored in repository

---

**Generated with Claude Code** 🤖