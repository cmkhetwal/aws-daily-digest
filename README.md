# AWS Executive Security Dashboard

Comprehensive AWS security monitoring system that provides daily executive security reports with business-critical instance monitoring, security group analysis, and IAM user activity tracking across multiple AWS accounts.

## Features

- 🔍 **Business-Critical Instance Monitoring**: Monitors specific critical instances for ANY port exposure (0.0.0.0/0)
- 🚨 **Advanced Risk Classification**: CRITICAL (critical instances), MEDIUM (non-critical + non-80/443), LOW (non-critical + 80/443 only)
- 👥 **IAM User Activity Tracking**: Real-time detection of user actions across 15+ AWS services
- 📧 **Professional HTML Reports**: Executive-style daily emails matching corporate dashboard format
- 📊 **Dual CSV Exports**: Complete security exposures + user activities for detailed analysis
- ⚡ **Multi-Region Scanning**: Monitors all regions across all AWS accounts from `~/.aws/credentials`

## Latest Version (2025-08-29)

### ✅ Executive Dashboard Complete
- **Business-Critical Focus**: Only flags instances from `critical-instances.txt` as CRITICAL
- **Professional HTML Email**: Dark blue header, executive styling, mobile-responsive
- **Smart Risk Logic**: Critical instances + ANY port = CRITICAL, Others classified by port type
- **Comprehensive Coverage**: 273 security exposures across all regions and accounts
- **IAM User Filtering**: Excludes automation, focuses on real user activities

### Comprehensive Service Coverage (15+ AWS Services)
- **EC2**: RunInstances, TerminateInstances, StartInstances, StopInstances, CreateSnapshot, DeleteSnapshot, CreateVolume, DeleteVolume, CreateImage, DeregisterImage, ModifyInstanceAttribute
- **IAM**: CreateUser, DeleteUser, AttachUserPolicy, DetachUserPolicy, CreateRole, DeleteRole, AttachRolePolicy, DetachRolePolicy, CreateAccessKey, DeleteAccessKey, EnableMFADevice, DeactivateMFADevice, ChangePassword, CreatePolicy, DeletePolicy
- **S3**: CreateBucket, DeleteBucket, PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl, PutObject, DeleteObject, PutBucketEncryption, DeleteBucketEncryption, PutBucketVersioning
- **VPC**: CreateVpc, DeleteVpc, CreateSubnet, DeleteSubnet, CreateInternetGateway, DeleteInternetGateway, CreateRouteTable, DeleteRouteTable, CreateRoute, DeleteRoute, CreateNatGateway, DeleteNatGateway
- **RDS**: CreateDBInstance, DeleteDBInstance, StartDBInstance, StopDBInstance, CreateDBCluster, DeleteDBCluster, CreateDBSnapshot, DeleteDBSnapshot, ModifyDBInstance
- **Lambda**: CreateFunction, DeleteFunction, UpdateFunctionCode, UpdateFunctionConfiguration, AddPermission, RemovePermission, CreateEventSourceMapping, DeleteEventSourceMapping
- **KMS**: CreateKey, ScheduleKeyDeletion, DisableKey, EnableKey, CreateGrant, RevokeGrant, PutKeyPolicy, EnableKeyRotation, DisableKeyRotation
- **CloudTrail**: CreateTrail, DeleteTrail, StartLogging, StopLogging, UpdateTrail, PutEventSelectors
- **CloudWatch**: PutMetricAlarm, DeleteAlarms, PutDashboard, DeleteDashboards, PutMetricData
- **GuardDuty**: CreateDetector, DeleteDetector, UpdateDetector, CreateIPSet, DeleteIPSet, CreateThreatIntelSet
- **Config**: PutConfigurationRecorder, DeleteConfigurationRecorder, PutConfigRule, DeleteConfigRule, StartConfigurationRecorder, StopConfigurationRecorder
- **Route53**: CreateHostedZone, DeleteHostedZone, ChangeResourceRecordSets, CreateHealthCheck, DeleteHealthCheck
- **ELB**: CreateLoadBalancer, DeleteLoadBalancer, CreateTargetGroup, DeleteTargetGroup, RegisterTargets, DeregisterTargets
- **AutoScaling**: CreateAutoScalingGroup, DeleteAutoScalingGroup, UpdateAutoScalingGroup, CreateLaunchConfiguration, DeleteLaunchConfiguration
- **SecretsManager**: CreateSecret, DeleteSecret, UpdateSecret, RestoreSecret, PutSecretValue, GetSecretValue

## Installation & Setup

### 1. Production Script
**Use this file for production:** `aws-comprehensive-security-dashboard.py`

```bash
# Copy to production server
scp aws-comprehensive-security-dashboard.py root@server:~/aws-security-dashboard/
scp critical-instances.txt root@server:~/aws-security-dashboard/
chmod +x ~/aws-security-dashboard/aws-comprehensive-security-dashboard.py
```

### 2. Dependencies
```bash
pip3 install boto3 --break-system-packages
```

### 3. Configure Critical Instances
**Update `critical-instances.txt` with your business-critical instance IDs:**
```bash
# critical-instances.txt - These instances trigger CRITICAL alerts for ANY port exposure
i-xxxxxxxxxxxxxxxxx
i-yyyyyyyyyyyyyyyyy  
i-zzzzzzzzzzzzzzzzz
```

### 4. Setup Daily Cron Job (9 AM)
```bash
crontab -e
# Add this line for daily 9 AM monitoring:
0 9 * * * cd /root/aws-security-dashboard && python3 aws-comprehensive-security-dashboard.py >> /var/log/aws-security-dashboard.log 2>&1
```

### 5. Test Manual Run
```bash
cd /root/aws-security-dashboard
python3 aws-comprehensive-security-dashboard.py
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
Update the email settings in `aws-comprehensive-security-dashboard.py`:
```python
SENDER_EMAIL = "no-reply@yourdomain.com"    # SES verified sender
RECIPIENT_EMAIL = "your-email@domain.com"
```

**SES Requirements:**
- Verify sender email in AWS SES console
- Verify recipient email in AWS SES console  
- Use appropriate AWS profile for SES sending

## Usage

### Manual Run
```bash
cd /root/aws-security-dashboard
python3 aws-comprehensive-security-dashboard.py
```

### Expected Output
```
=== AWS Comprehensive Security Dashboard ===
Started at: 2025-08-29 18:22:05
🚀 Starting AWS Comprehensive Security Dashboard...
🔍 Scanning security groups across all AWS accounts and regions...
📋 Discovered 3 AWS profiles: account1, account2, account3
🎯 Critical instance patterns: 3

✅ Security group scan complete:
   🔴 CRITICAL: 0 exposures  (your critical instances are secure!)
   🟡 MEDIUM: 83 exposures   (non-critical instances + non-80/443 ports)
   🟢 LOW: 190 exposures     (non-critical instances + only 80/443 ports)
   📊 TOTAL: 273 exposures

🔍 Detecting IAM user activities in last 48 hours...
✅ Found 25 user activities

✅ CSV files created:
   📄 Security exposures: security-exposures-2025-08-29.csv (273 rows)
   📄 User activities: user-activities-2025-08-29.csv (25 rows)

📧 Sending comprehensive security dashboard...
✅ COMPREHENSIVE SECURITY DASHBOARD SENT SUCCESSFULLY!
📧 MessageId: xxxxx-xxxx-xxxx-xxxx-xxxxx
🔴 Critical exposures: 0
🟡 Medium exposures: 83
🟢 Low exposures: 190
👤 User activities: 25
```

## Risk Classification

### Business-Critical Instance Focus
- **🔴 CRITICAL**: ANY port exposed to 0.0.0.0/0 on instances in `critical-instances.txt` 
  - Triggers immediate email alert in email body
  - These are your business-critical production instances
- **🟡 MEDIUM**: Non-critical instances with ports other than 80/443 exposed to 0.0.0.0/0
  - Logged in CSV only (SSH, MySQL, custom ports, etc.)
- **🟢 LOW**: Non-critical instances with only HTTP/HTTPS (80/443) exposed to 0.0.0.0/0
  - Logged in CSV only (normal web traffic)

## Report Contents

Daily reports include:
- **Comprehensive CloudTrail Events**: All activities across 15+ AWS services in last 24 hours
- **Critical Changes**: High-risk actions flagged for immediate attention
- **Security Group Analysis**: Complete risk breakdown with internet-exposed groups
- **Service Monitoring Summary**: Status of all 15 monitored AWS services
- **Dual CSV Attachments**: 
  1. `security-groups-comprehensive.csv` - All internet-exposed security groups
  2. `comprehensive-aws-events.csv` - All administrative changes by category
- **Immediate action recommendations** for critical security issues

## Critical Event Detection

The system now identifies 35+ critical events across all services including:
- **Destructive Actions**: TerminateInstances, DeleteSnapshot, DeleteUser, DeleteBucket
- **Permission Changes**: DetachUserPolicy, RevokeGrant, RemovePermission
- **Infrastructure Deletion**: DeleteVpc, DeleteTrail, DeleteFunction
- **Security Disabling**: DisableKey, StopLogging, DeleteDetector

## Files

- `aws-comprehensive-security-dashboard.py` - **Main production script** (use this one)
- `critical-instances.txt` - Business-critical instance definitions (required)  
- `README.md` - This documentation

### Deprecated Files (Do Not Use)
- `final-comprehensive-check.py` - Old testing script
- `send-comprehensive-report.py` - Old version

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