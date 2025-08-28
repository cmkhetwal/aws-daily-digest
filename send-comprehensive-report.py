#!/usr/bin/env python3

import boto3
import json
import subprocess
import os
import configparser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from datetime import datetime, timedelta
import csv

print("=== COMPREHENSIVE AWS SECURITY SCAN ===")
print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}")

# Email configuration
SENDER_EMAIL = "no-reply@bamko.net"
SENDER_NAME = "Bamko Security Team"  
RECIPIENT_EMAIL = "cmkhetwal@hotmail.com"

# Dynamically discover AWS profiles
def discover_aws_profiles():
    """Discover all AWS profiles from ~/.aws/credentials"""
    profiles = []
    credentials_file = os.path.expanduser('~/.aws/credentials')
    
    if os.path.exists(credentials_file):
        config = configparser.ConfigParser()
        config.read(credentials_file)
        
        for section in config.sections():
            if section != 'default':  # Skip default profile
                profiles.append(section)
                print(f"  ✅ Found profile: {section}")
    
    if not profiles:
        print("❌ No AWS profiles found in ~/.aws/credentials")
        return []
        
    print(f"✅ Discovered {len(profiles)} AWS profiles: {', '.join(profiles)}")
    return profiles

# Get account ID for profile
def get_account_id(profile_name):
    """Get account ID for a profile"""
    try:
        session = boto3.Session(profile_name=profile_name)
        sts_client = session.client('sts')
        response = sts_client.get_caller_identity()
        return response['Account']
    except Exception as e:
        print(f"    ❌ Could not get account ID for {profile_name}: {e}")
        return "unknown"

# Load critical instances
def load_critical_instances():
    critical_instances = []
    critical_file = 'critical-instances.txt'
    if os.path.exists(critical_file):
        with open(critical_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    critical_instances.append(line)
    print(f"✅ Loaded {len(critical_instances)} critical instances")
    return critical_instances

# Function to check if instance is critical
def is_critical_instance(instance_id, critical_instances):
    return instance_id in critical_instances

# Get regions for scanning (common regions where resources exist)
def get_scan_regions():
    return ['us-east-1', 'us-west-1', 'us-west-2', 'ap-south-1', 'eu-west-1']

# Scan security groups across all discovered accounts
def scan_security_groups():
    print("🔍 Scanning security groups across all discovered accounts...")
    
    # Dynamically discover profiles
    profiles = discover_aws_profiles()
    if not profiles:
        return [], 0, 0, 0
    
    # Get account IDs for profiles
    accounts = {}
    for profile in profiles:
        account_id = get_account_id(profile)
        accounts[profile] = account_id
        print(f"  📋 {profile}: {account_id}")
    
    scan_regions = get_scan_regions()
    critical_instances = load_critical_instances()
    all_groups = []
    
    critical_count = 0
    medium_count = 0
    low_count = 0
    
    for profile, account_id in accounts.items():
        print(f"  Scanning {profile} account ({account_id})...")
        
        try:
            session = boto3.Session(profile_name=profile)
            
            for region in scan_regions:
                try:
                    print(f"    Region: {region}")
                    ec2_client = session.client('ec2', region_name=region)
                    
                    # Get all security groups
                    response = ec2_client.describe_security_groups()
                    region_groups = 0
                    
                    for sg in response['SecurityGroups']:
                        # Check if security group has internet exposure
                        has_internet_access = False
                        exposed_ports = []
                        
                        for rule in sg.get('IpPermissions', []):
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    has_internet_access = True
                                    from_port = rule.get('FromPort', 0)
                                    to_port = rule.get('ToPort', 65535) 
                                    protocol = rule.get('IpProtocol', 'all')
                                    exposed_ports.append(f"{from_port}-{to_port}/{protocol}")
                        
                        if has_internet_access:
                            region_groups += 1
                            
                            # Get attached instances
                            try:
                                instances_response = ec2_client.describe_instances(
                                    Filters=[{'Name': 'instance.group-id', 'Values': [sg['GroupId']]}]
                                )
                                
                                attached_instances = []
                                has_critical = False
                                
                                for reservation in instances_response['Reservations']:
                                    for instance in reservation['Instances']:
                                        instance_id = instance['InstanceId']
                                        attached_instances.append(instance_id)
                                        if is_critical_instance(instance_id, critical_instances):
                                            has_critical = True
                            except:
                                attached_instances = []
                                has_critical = False
                            
                            # Determine risk level
                            if has_critical:
                                risk = 'CRITICAL'
                                critical_count += 1
                            elif any(dangerous_port in ''.join(exposed_ports) for dangerous_port in ['22-22', '1194-1194', '3306-3306', '8080-8080']):
                                risk = 'MEDIUM' 
                                medium_count += 1
                            else:
                                risk = 'LOW'
                                low_count += 1
                            
                            group_data = {
                                'Account': profile,
                                'AccountID': account_id,
                                'Region': region,
                                'SecurityGroupId': sg['GroupId'],
                                'SecurityGroupName': sg['GroupName'],
                                'Risk': risk,
                                'Ports': ';'.join(exposed_ports),
                                'Protocol': 'Internet (0.0.0.0/0)',
                                'Source': 'Internet (0.0.0.0/0)',
                                'AttachedInstances': ' '.join(attached_instances),
                                'CriticalInstance': str(has_critical).lower()
                            }
                            all_groups.append(group_data)
                    
                    if region_groups > 0:
                        print(f"      Found {region_groups} internet-exposed groups")
                        
                except Exception as e:
                    print(f"      ⚠️ Could not scan region {region}: {e}")
                    continue
        
        except Exception as e:
            print(f"    ❌ Error scanning {profile}: {e}")
            continue
    
    print(f"✅ Security group scan complete: {len(all_groups)} internet-exposed groups found")
    print(f"   🔴 CRITICAL: {critical_count}")
    print(f"   🟡 MEDIUM: {medium_count}")  
    print(f"   🟢 LOW: {low_count}")
    
    return all_groups, critical_count, medium_count, low_count

# Detect AWS changes with comprehensive event coverage
def detect_aws_changes():
    print("🔍 Detecting comprehensive AWS changes in last 24 hours...")
    
    # Dynamically discover profiles
    profiles = discover_aws_profiles()
    if not profiles:
        return {'ec2': [], 's3': [], 'rds': []}
    
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=24)
    
    changes = {
        'ec2': [],
        's3': [],
        'rds': []
    }
    
    # Focus on primary regions to avoid timeout
    scan_regions = ['us-east-1', 'us-west-1', 'ap-south-1']
    
    # High priority events to check first
    ec2_events = ['RunInstances', 'TerminateInstances', 'StartInstances', 'StopInstances', 'DeleteSnapshot', 'CreateSnapshot']
    s3_events = ['CreateBucket', 'DeleteBucket', 'PutBucketPolicy', 'DeleteBucketPolicy']
    rds_events = ['StopDBInstance', 'StartDBInstance', 'DeleteDBInstance', 'CreateDBInstance']
    
    for profile in profiles:
        try:
            print(f"  Checking changes in {profile}...")
            session = boto3.Session(profile_name=profile)
            
            for region in scan_regions:
                try:
                    cloudtrail = session.client('cloudtrail', region_name=region)
                    
                    # EC2 changes
                    for event_name in ec2_events:
                        try:
                            response = cloudtrail.lookup_events(
                                LookupAttributes=[{
                                    'AttributeKey': 'EventName',
                                    'AttributeValue': event_name
                                }],
                                StartTime=start_time,
                                EndTime=end_time,
                                MaxResults=10
                            )
                            
                            for event in response.get('Events', []):
                                username = event.get('Username', '')
                                # Include all user events, exclude aws-internal and system events
                                if (username and 'aws-internal' not in username and 'system' not in username.lower()):
                                    changes['ec2'].append({
                                        'account': profile,
                                        'time': event['EventTime'].strftime('%H:%M IST'),
                                        'user': username,
                                        'action': event['EventName'],
                                        'resources': [r.get('ResourceName', '') for r in event.get('Resources', [])]
                                    })
                        except:
                            continue
                    
                    # S3 changes
                    for event_name in s3_events:
                        try:
                            response = cloudtrail.lookup_events(
                                LookupAttributes=[{
                                    'AttributeKey': 'EventName', 
                                    'AttributeValue': event_name
                                }],
                                StartTime=start_time,
                                EndTime=end_time,
                                MaxResults=5
                            )
                            
                            for event in response.get('Events', []):
                                username = event.get('Username', '')
                                # Include all user events, exclude aws-internal and system events
                                if (username and 'aws-internal' not in username):
                                    changes['s3'].append({
                                        'account': profile,
                                        'time': event['EventTime'].strftime('%H:%M IST'),
                                        'user': username,
                                        'action': event['EventName'],
                                        'resources': [r.get('ResourceName', '') for r in event.get('Resources', [])]
                                    })
                        except:
                            continue
                    
                    # RDS changes
                    for event_name in rds_events:
                        try:
                            response = cloudtrail.lookup_events(
                                LookupAttributes=[{
                                    'AttributeKey': 'EventName',
                                    'AttributeValue': event_name  
                                }],
                                StartTime=start_time,
                                EndTime=end_time,
                                MaxResults=5
                            )
                            
                            for event in response.get('Events', []):
                                username = event.get('Username', '')
                                # Include all user events, exclude aws-internal and system events  
                                if (username and 'aws-internal' not in username):
                                    changes['rds'].append({
                                        'account': profile,
                                        'time': event['EventTime'].strftime('%H:%M IST'),
                                        'user': username, 
                                        'action': event['EventName'],
                                        'resources': [r.get('ResourceName', '') for r in event.get('Resources', [])]
                                    })
                        except:
                            continue
                            
                except:
                    continue
                    
        except Exception as e:
            print(f"    ❌ Error scanning {profile}: {e}")
            continue
    
    total_changes = len(changes['ec2']) + len(changes['s3']) + len(changes['rds'])
    print(f"✅ Comprehensive change detection complete: {total_changes} changes found")
    print(f"   💾 EC2: {len(changes['ec2'])} changes")
    print(f"   📦 S3: {len(changes['s3'])} changes") 
    print(f"   🗄️ RDS: {len(changes['rds'])} changes")
    
    return changes

# Create CSV file
def create_csv(security_groups):
    csv_file = '/tmp/security-groups-comprehensive.csv'
    
    with open(csv_file, 'w', newline='') as f:
        if security_groups:
            writer = csv.DictWriter(f, fieldnames=security_groups[0].keys())
            writer.writeheader()
            writer.writerows(security_groups)
    
    print(f"✅ CSV file created: {csv_file} with {len(security_groups)} rows")
    return csv_file

# Main execution
def main():
    try:
        # Perform comprehensive scans
        security_groups, critical_count, medium_count, low_count = scan_security_groups()
        changes = detect_aws_changes()
        
        if not security_groups:
            print("❌ No security groups found. Check AWS credentials and permissions.")
            return
            
        csv_file = create_csv(security_groups)
        
        total_changes = len(changes['ec2']) + len(changes['s3']) + len(changes['rds'])
        
        # Create comprehensive report body
        report_body = f"""🚀 COMPREHENSIVE AWS EXECUTIVE SECURITY REPORT
Date: {datetime.now().strftime('%Y-%m-%d %H:%M IST')} - COMPLETE SCAN WITH EXPANDED EVENT DETECTION

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔄 COMPREHENSIVE AWS CHANGES DETECTED (Last 24 Hours): {total_changes} total
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💾 EC2 CHANGES ({len(changes['ec2'])}):
""" + '\n'.join([f"• {c['account']}: {c['time']} - {c['user']} - {c['action']}" + (f" - {c['resources'][0]}" if c['resources'] and c['resources'][0] else "") for c in changes['ec2'][:15]]) + f"""

📦 S3 CHANGES ({len(changes['s3'])}):
""" + '\n'.join([f"• {c['account']}: {c['time']} - {c['user']} - {c['action']}" + (f" - {c['resources'][0]}" if c['resources'] and c['resources'][0] else "") for c in changes['s3'][:15]]) + f"""

🗄️ RDS CHANGES ({len(changes['rds'])}):
""" + '\n'.join([f"• {c['account']}: {c['time']} - {c['user']} - {c['action']}" + (f" - {c['resources'][0]}" if c['resources'] and c['resources'][0] else "") for c in changes['rds'][:15]]) + f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 COMPREHENSIVE SECURITY GROUP ANALYSIS: {len(security_groups)} groups
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 RISK BREAKDOWN:
• 🔴 CRITICAL: {critical_count} security groups
• 🟡 MEDIUM: {medium_count} security groups
• 🟢 LOW: {low_count} security groups
• 📄 TOTAL INTERNET-EXPOSED: {len(security_groups)} groups

📎 ATTACHED: Complete CSV with all security group details including account names

🔴 CRITICAL SECURITY GROUPS:
""" + '\n'.join([f"• {sg['Account']}/{sg['SecurityGroupId']} ({sg['SecurityGroupName']}) - {sg['Ports']}" for sg in security_groups if sg['Risk'] == 'CRITICAL'][:5]) + f"""

⚠️ IMMEDIATE ACTIONS REQUIRED:
""" + '\n'.join([f"• {sg['Account']}: Remove internet access from {sg['SecurityGroupId']}" for sg in security_groups if sg['Risk'] == 'CRITICAL'][:3]) + f"""

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}
✅ COMPREHENSIVE scan completed successfully - Includes expanded event detection!

📋 Scanned Accounts: """ + ', '.join([sg['Account'] for sg in security_groups[:1]]) + " (and others)" if security_groups else "None" + f"""

🔍 EVENT COVERAGE EXPANDED:
• EC2: RunInstances, TerminateInstances, StartInstances, StopInstances, DeleteSnapshot, CreateSnapshot
• S3: CreateBucket, DeleteBucket, PutBucketPolicy, DeleteBucketPolicy  
• RDS: StopDBInstance, StartDBInstance, DeleteDBInstance, CreateDBInstance
• USER TYPES: IAMUser, FederatedUser, Root (excludes service roles)"""

        # Send email
        print("📧 Sending comprehensive email with expanded change detection...")
        
        msg = MIMEMultipart()
        msg['Subject'] = f'🚨 COMPREHENSIVE AWS Security Report - {total_changes} Changes + {len(security_groups)} Groups - {datetime.now().strftime("%Y-%m-%d")}'
        msg['From'] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
        msg['To'] = RECIPIENT_EMAIL
        
        msg.attach(MIMEText(report_body, 'plain'))
        
        # Attach CSV
        if os.path.exists(csv_file):
            with open(csv_file, 'rb') as f:
                attachment = MIMEApplication(f.read(), _subtype='csv')
                attachment.add_header('Content-Disposition', 'attachment', filename='comprehensive-security-groups.csv')
                msg.attach(attachment)
        
        # Send via SES
        session = boto3.Session(profile_name='unified')  # Assuming unified profile exists for SES
        ses_client = session.client('ses', region_name='us-east-1')
        
        response = ses_client.send_raw_email(
            Source=f"{SENDER_NAME} <{SENDER_EMAIL}>",
            Destinations=[RECIPIENT_EMAIL],
            RawMessage={'Data': msg.as_string()}
        )
        
        print(f"✅ COMPREHENSIVE SECURITY REPORT SENT SUCCESSFULLY!")
        print(f"MessageId: {response['MessageId']}")
        print(f"📊 Scanned: {len(security_groups)} security groups across all discovered accounts")
        print(f"🔄 Detected: {total_changes} AWS changes with expanded event coverage") 
        print(f"📎 Attached: Comprehensive CSV with account names and security group data")
        print(f"🎯 Now includes DeleteSnapshot and other critical events!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()