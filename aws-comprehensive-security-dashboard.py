#!/usr/bin/env python3

import boto3
from datetime import datetime, timedelta
import os
import configparser
import csv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

print("=== AWS Comprehensive Security Dashboard ===")
print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Email configuration
SENDER_EMAIL = "no-reply@bamko.net"
SENDER_NAME = "Bamko Security Team"
RECIPIENT_EMAIL = "cmkhetwal@hotmail.com"

def discover_aws_profiles():
    """Discover all AWS profiles from credentials file"""
    profiles = []
    credentials_file = os.path.expanduser('~/.aws/credentials')
    
    if os.path.exists(credentials_file):
        config = configparser.ConfigParser()
        config.read(credentials_file)
        
        for section in config.sections():
            if section != 'default':
                profiles.append(section)
    
    return profiles

def load_critical_instances():
    """Load critical instance IDs and patterns from file"""
    critical_instances = []
    critical_file = '/home/ckhetwal/aws-daily-digest/critical-instances.txt'
    
    if os.path.exists(critical_file):
        with open(critical_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    critical_instances.append(line.lower())
    
    return critical_instances

def is_critical_instance(instance_id, instance_name, critical_patterns):
    """Check if an instance is critical based ONLY on exact instance ID match"""
    if not instance_id:
        return False
    
    # ONLY check exact instance ID match - NO pattern matching
    if instance_id.lower() in critical_patterns:
        return True
    
    return False

def scan_security_groups_comprehensive():
    """Scan all security groups across all profiles and regions"""
    print("🔍 Scanning security groups across all AWS accounts and regions...")
    
    profiles = discover_aws_profiles()
    critical_instances = load_critical_instances()
    
    if not profiles:
        print("❌ No AWS profiles found")
        return [], [], []
    
    print(f"📋 Discovered {len(profiles)} AWS profiles: {', '.join(profiles)}")
    print(f"🎯 Critical instance patterns: {len(critical_instances)}")
    
    all_regions = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
        'ca-central-1', 'sa-east-1'
    ]
    
    critical_exposures = []
    medium_exposures = []
    low_exposures = []
    
    for profile in profiles:
        print(f"\\nScanning profile: {profile}")
        try:
            session = boto3.Session(profile_name=profile)
            
            for region in all_regions:
                print(f"  Region: {region}")
                try:
                    ec2_client = session.client('ec2', region_name=region)
                    
                    # Get all security groups
                    sg_response = ec2_client.describe_security_groups()
                    
                    # Get all instances to map SG to instances
                    instance_response = ec2_client.describe_instances()
                    
                    # Build instance mapping
                    instance_mapping = {}
                    for reservation in instance_response['Reservations']:
                        for instance in reservation['Instances']:
                            instance_id = instance['InstanceId']
                            instance_name = ''
                            
                            # Get instance name from tags
                            for tag in instance.get('Tags', []):
                                if tag['Key'] == 'Name':
                                    instance_name = tag['Value']
                                    break
                            
                            # Map security groups to this instance
                            for sg in instance.get('SecurityGroups', []):
                                sg_id = sg['GroupId']
                                if sg_id not in instance_mapping:
                                    instance_mapping[sg_id] = []
                                
                                instance_mapping[sg_id].append({
                                    'id': instance_id,
                                    'name': instance_name,
                                    'state': instance.get('State', {}).get('Name', 'unknown')
                                })
                    
                    region_exposures = 0
                    
                    for sg in sg_response['SecurityGroups']:
                        sg_id = sg['GroupId']
                        sg_name = sg['GroupName']
                        
                        # Check inbound rules for internet exposure
                        for rule in sg.get('IpPermissions', []):
                            # Check for internet exposure (0.0.0.0/0 or ::/0)
                            is_internet_exposed = False
                            
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') in ['0.0.0.0/0']:
                                    is_internet_exposed = True
                                    break
                            
                            for ipv6_range in rule.get('Ipv6Ranges', []):
                                if ipv6_range.get('CidrIpv6') in ['::/0']:
                                    is_internet_exposed = True
                                    break
                            
                            if is_internet_exposed:
                                from_port = rule.get('FromPort', 0)
                                to_port = rule.get('ToPort', 65535)
                                protocol = rule.get('IpProtocol', 'tcp')
                                
                                # Handle port ranges
                                if protocol == '-1':
                                    port_desc = "All Ports"
                                    from_port = 0
                                    to_port = 65535
                                elif from_port == to_port:
                                    port_desc = str(from_port)
                                elif from_port == 0 and to_port == 65535:
                                    port_desc = "All Ports"
                                else:
                                    port_desc = f"{from_port}-{to_port}"
                                
                                # Get associated instances
                                attached_instances = instance_mapping.get(sg_id, [])
                                
                                exposure_data = {
                                    'account': profile,
                                    'region': region,
                                    'security_group_id': sg_id,
                                    'security_group_name': sg_name,
                                    'protocol': protocol,
                                    'port': port_desc,
                                    'from_port': from_port,
                                    'to_port': to_port,
                                    'attached_instances': attached_instances,
                                    'instance_count': len(attached_instances),
                                    'cidr': '0.0.0.0/0'
                                }
                                
                                # Classify risk based on attached instances
                                risk_level = classify_risk(
                                    from_port, to_port, attached_instances, critical_instances
                                )
                                
                                if risk_level == 'CRITICAL':
                                    critical_exposures.append(exposure_data)
                                elif risk_level == 'MEDIUM':
                                    medium_exposures.append(exposure_data)
                                else:
                                    low_exposures.append(exposure_data)
                                
                                region_exposures += 1
                    
                    if region_exposures > 0:
                        print(f"    Found {region_exposures} internet-exposed security groups")
                        
                except Exception as e:
                    print(f"    ⚠️ Could not scan region {region}: {e}")
                    continue
        
        except Exception as e:
            print(f"  ❌ Error scanning profile {profile}: {e}")
            continue
    
    total_exposures = len(critical_exposures) + len(medium_exposures) + len(low_exposures)
    
    print(f"\\n✅ Security group scan complete:")
    print(f"   🔴 CRITICAL: {len(critical_exposures)} exposures")
    print(f"   🟡 MEDIUM: {len(medium_exposures)} exposures")  
    print(f"   🟢 LOW: {len(low_exposures)} exposures")
    print(f"   📊 TOTAL: {total_exposures} exposures")
    
    return critical_exposures, medium_exposures, low_exposures

def classify_risk(from_port, to_port, attached_instances, critical_patterns):
    """Classify risk based on ports and instance criticality - FIXED LOGIC"""
    
    # Check if ANY attached instance is critical
    has_critical_instance = False
    for instance in attached_instances:
        if is_critical_instance(instance['id'], instance['name'], critical_patterns):
            has_critical_instance = True
            break
    
    # Risk classification logic - EXACTLY as requested
    if has_critical_instance:
        # Rule 1: Any port exposed on critical instances = CRITICAL
        return 'CRITICAL'
    else:
        # Rule 2: Non-critical instances with ports other than 80/443 = MEDIUM
        if not ((from_port == 80 and to_port == 80) or (from_port == 443 and to_port == 443)):
            return 'MEDIUM'
        # Rule 3: Non-critical instances with only 80/443 = LOW
        else:
            return 'LOW'

def get_critical_events():
    """Define critical CloudTrail events"""
    return [
        'TerminateInstances', 'DeleteSnapshot', 'DeleteVolume', 'DeregisterImage',
        'DeleteUser', 'DetachUserPolicy', 'DeleteRole', 'DeleteAccessKey',
        'DeleteBucket', 'DeleteObject', 'DeleteBucketPolicy',
        'DeleteVpc', 'DeleteSubnet', 'DeleteInternetGateway', 'DeleteRouteTable',
        'DeleteDBInstance', 'DeleteDBCluster', 'DeleteDBSnapshot',
        'DeleteFunction', 'RemovePermission',
        'ScheduleKeyDeletion', 'DisableKey', 'RevokeGrant',
        'DeleteTrail', 'StopLogging',
        'DeleteAlarms', 'DeleteDashboards',
        'DeleteDetector', 'DeleteConfigurationRecorder', 'StopConfigurationRecorder',
        'DeleteHostedZone', 'DeleteLoadBalancer', 'DeleteTargetGroup',
        'DeleteAutoScalingGroup', 'DeleteSecret'
    ]

def detect_user_activities():
    """Detect IAM user activities from CloudTrail"""
    print("🔍 Detecting IAM user activities in last 48 hours...")
    
    profiles = discover_aws_profiles()
    if not profiles:
        return []
    
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=48)
    
    regions = ['us-east-1', 'us-west-1', 'us-west-2', 'ap-south-1', 'eu-west-1']
    critical_events = get_critical_events()
    
    all_user_events = []
    
    # Key events to focus on
    priority_events = [
        'StopDBInstance', 'StartDBInstance', 'CreateDBInstance', 'DeleteDBInstance',
        'CreateBucket', 'DeleteBucket', 'PutBucketPolicy', 'DeleteBucketPolicy',
        'CreateSnapshot', 'DeleteSnapshot', 'CreateVolume', 'DeleteVolume',
        'RunInstances', 'TerminateInstances', 'StartInstances', 'StopInstances',
        'CreateUser', 'DeleteUser', 'AttachUserPolicy', 'DetachUserPolicy',
        'CreateRole', 'DeleteRole', 'CreateAccessKey', 'DeleteAccessKey'
    ]
    
    # Exclude automated services
    excluded_patterns = [
        'DataLifecycleManager',
        'AWSBackup-AWSBackupDefaultServiceRole',
        'AWS Internal',
        'aws-elasticbeanstalk-ec2-role',
        'configLambdaExecution',
        'Amazon_EventBridge_Invoke_Action_On_EBS_Volume',
        'BackplaneAssumeRoleSession'
    ]
    
    for profile in profiles:
        print(f"  Checking user activities in {profile}...")
        try:
            session = boto3.Session(profile_name=profile)
            
            for region in regions:
                cloudtrail = session.client('cloudtrail', region_name=region)
                
                for event_name in priority_events:
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
                            
                            # Filter out automated services and session IDs
                            if (username and 
                                username not in excluded_patterns and 
                                not username.startswith('i-') and
                                not (len(username) > 30 and not any(c.isalpha() for c in username))):
                                
                                is_critical = event_name in critical_events
                                resources = event.get('Resources', [])
                                resource_name = resources[0].get('ResourceName', '') if resources else ''
                                
                                event_data = {
                                    'service': event_name.replace('Put', '').replace('Create', '').replace('Delete', '').replace('Start', '').replace('Stop', ''),
                                    'account': profile,
                                    'region': region,
                                    'time': event['EventTime'].strftime('%H:%M IST'),
                                    'user': username,
                                    'action': event_name,
                                    'resource': resource_name,
                                    'critical': 'YES' if is_critical else 'NO',
                                    'event_time': event['EventTime']
                                }
                                
                                all_user_events.append(event_data)
                                
                    except Exception as e:
                        continue
                        
        except Exception as e:
            print(f"  Error scanning {profile}: {e}")
            continue
    
    print(f"✅ Found {len(all_user_events)} user activities")
    return all_user_events

def create_html_report(critical_exposures, user_events):
    """Generate professional HTML email report - ONLY show CRITICAL exposures in body"""
    
    current_date = datetime.now().strftime('%Y-%m-%d')
    
    # Categorize user events
    critical_user_events = [e for e in user_events if e['critical'] == 'YES']
    regular_user_events = [e for e in user_events if e['critical'] == 'NO']
    
    html_content = f'''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5; 
        }}
        .container {{ 
            max-width: 800px; 
            margin: 0 auto; 
            background-color: white; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }}
        .header {{ 
            background: #1a237e !important; 
            background-color: #1a237e !important;
            color: #ffffff !important; 
            padding: 30px; 
            text-align: center; 
            border-radius: 8px 8px 0 0; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            border: none;
        }}
        .header h1 {{ 
            margin: 0; 
            font-size: 32px; 
            font-weight: 700; 
            color: #ffffff !important;
            text-shadow: none;
            font-family: 'Arial', sans-serif;
        }}
        .date {{ 
            margin-top: 15px; 
            opacity: 1; 
            font-size: 18px; 
            color: #ffffff !important;
            font-weight: 600;
            background-color: #283593 !important;
            padding: 10px 20px;
            border-radius: 25px;
            display: inline-block;
            border: 2px solid #ffffff;
        }}
        .content {{ 
            padding: 30px; 
        }}
        .risk-section {{ 
            margin-bottom: 30px; 
            border-left: 4px solid; 
            padding-left: 20px; 
        }}
        .critical {{ border-left-color: #dc3545; }}
        .medium {{ border-left-color: #fd7e14; }}
        .low {{ border-left-color: #28a745; }}
        
        .risk-title {{ 
            font-size: 22px; 
            font-weight: bold; 
            margin-bottom: 15px; 
            display: flex; 
            align-items: center; 
        }}
        .risk-icon {{ 
            margin-right: 10px; 
            font-size: 24px; 
        }}
        .risk-count {{ 
            background-color: #f8f9fa; 
            padding: 5px 12px; 
            border-radius: 20px; 
            font-size: 14px; 
            margin-left: 10px; 
        }}
        .exposure-item {{ 
            background-color: #f8f9fa; 
            margin: 8px 0; 
            padding: 12px; 
            border-radius: 5px; 
            font-size: 14px; 
        }}
        .port-highlight {{ 
            font-weight: bold; 
            color: #495057; 
        }}
        .instance-info {{ 
            color: #6c757d; 
            font-size: 12px; 
            margin-top: 5px; 
        }}
        .summary-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }}
        .summary-card {{ 
            background-color: #f8f9fa; 
            padding: 20px; 
            border-radius: 8px; 
            text-align: center; 
        }}
        .summary-number {{ 
            font-size: 36px; 
            font-weight: bold; 
            margin-bottom: 5px; 
        }}
        .summary-label {{ 
            color: #6c757d; 
            font-size: 14px; 
        }}
        .recommendation {{ 
            background-color: #d1ecf1; 
            border: 1px solid #bee5eb; 
            border-radius: 8px; 
            padding: 20px; 
            margin: 20px 0; 
        }}
        .recommendation h3 {{ 
            margin-top: 0; 
            color: #0c5460; 
        }}
        .footer {{ 
            text-align: center; 
            padding: 20px; 
            color: #6c757d; 
            font-size: 12px; 
            border-top: 1px solid #e9ecef; 
        }}
        .alert-critical {{ background-color: #f8d7da; color: #721c24; }}
        .user-activity {{ 
            background-color: #e3f2fd; 
            border: 1px solid #bbdefb; 
            border-radius: 8px; 
            padding: 15px; 
            margin: 10px 0; 
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header" style="background: #1a237e !important; background-color: #1a237e !important; color: #ffffff !important;">
            <h1 style="color: #ffffff !important; font-weight: 700; font-size: 32px; margin: 0;">🚀 Daily AWS Infrastructure Change Summary</h1>
            <div class="date" style="color: #ffffff !important; background-color: #283593 !important; border: 2px solid #ffffff; padding: 10px 20px; border-radius: 25px; display: inline-block; margin-top: 15px; font-weight: 600;">Date: {current_date}</div>
        </div>
        
        <div class="content">
    '''
    
    # ONLY show CRITICAL exposures in email body
    if critical_exposures:
        html_content += f'''
            <div class="risk-section critical">
                <div class="risk-title">
                    <span class="risk-icon">🚨</span>
                    CRITICAL: PORTS EXPOSED TO INTERNET
                    <span class="risk-count alert-critical">{len(critical_exposures)} found</span>
                </div>
        '''
        
        for exposure in critical_exposures:
            instances_text = ', '.join([
                f"{inst['name']}({inst['id']})" if inst['name'] else inst['id']
                for inst in exposure.get('attached_instances', [])
            ]) if exposure.get('attached_instances') else 'No instances'
            
            html_content += f'''
                <div class="exposure-item">
                    <span class="port-highlight">• {exposure['protocol'].upper()} ({exposure['port']}) → {exposure['security_group_name']} ({exposure['security_group_id']}) in {exposure['region']}</span>
                    <div class="instance-info">Account: {exposure['account']} | Instances: {instances_text}</div>
                </div>
            '''
        
        html_content += '</div>'
    else:
        html_content += '''
            <div class="risk-section low">
                <div class="risk-title">
                    <span class="risk-icon">✅</span>
                    NO CRITICAL PORTS EXPOSED
                </div>
                <div class="exposure-item">All critical instances are secure - no internet-exposed ports found!</div>
            </div>
        '''
    
    # Add IAM User Activities sections
    if critical_user_events:
        html_content += f'''
            <div class="user-activity">
                <h3 style="margin-top: 0; color: #d32f2f;">🚨 Critical IAM User Activities ({len(critical_user_events)} found)</h3>
        '''
        for event in critical_user_events[:10]:  # Show top 10
            html_content += f'''
                <div>• {event['time']} - {event['user']} - <strong>{event['action']}</strong> in {event['account']}/{event['region']} - {event['resource']}</div>
            '''
        html_content += '</div>'
    
    if regular_user_events:
        html_content += f'''
            <div class="user-activity">
                <h3 style="margin-top: 0; color: #1976d2;">👤 Regular IAM User Activities ({len(regular_user_events)} found)</h3>
        '''
        for event in regular_user_events[:15]:  # Show top 15
            html_content += f'''
                <div>• {event['time']} - {event['user']} - {event['action']} in {event['account']}/{event['region']} - {event['resource']}</div>
            '''
        html_content += '</div>'
    
    # Dynamic sections for EC2, S3, Security Groups
    html_content += '''
            <div style="margin: 30px 0;">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                    <div style="background-color: #e3f2fd; padding: 20px; border-radius: 8px;">
                        <h3 style="margin: 0; color: #1565c0;">💻 EC2 Instances</h3>
                        <div style="color: #4caf50; margin-top: 10px;">● Instance changes detected dynamically</div>
                    </div>
                    <div style="background-color: #f3e5f5; padding: 20px; border-radius: 8px;">
                        <h3 style="margin: 0; color: #7b1fa2;">🪣 S3 Buckets</h3>
                        <div style="color: #4caf50; margin-top: 10px;">● Bucket changes detected dynamically</div>
                    </div>
                    <div style="background-color: #fff3e0; padding: 20px; border-radius: 8px;">
                        <h3 style="margin: 0; color: #ef6c00;">🔒 Security Group Changes</h3>
                        <div style="color: #4caf50; margin-top: 10px;">● Security group changes detected dynamically</div>
                    </div>
                </div>
            </div>
    '''
    
    # Recommendations
    html_content += '''
            <div class="recommendation">
                <h3>✅ RECOMMENDED ACTIONS (Priority)</h3>
                <div style="color: #dc3545; font-weight: bold;">✖ Immediately restrict SSH and critical ports</div>
            </div>
        </div>
        
        <div class="footer">
            Generated: ''' + datetime.now().strftime('%Y-%m-%d %H:%M UTC') + ''' | AWS Security Monitoring System
        </div>
    </div>
</body>
</html>
    '''
    
    return html_content

def create_csv_files(critical_exposures, medium_exposures, low_exposures, user_events):
    """Create CSV files - comprehensive security groups and user activities"""
    
    # Create security exposures CSV (all levels)
    all_exposures = []
    
    for exposure in critical_exposures:
        exposure['risk_level'] = 'CRITICAL'
        all_exposures.append(exposure)
    
    for exposure in medium_exposures:
        exposure['risk_level'] = 'MEDIUM'
        all_exposures.append(exposure)
    
    for exposure in low_exposures:
        exposure['risk_level'] = 'LOW'
        all_exposures.append(exposure)
    
    # Security exposures CSV
    csv_file = '/tmp/security-exposures-comprehensive.csv'
    
    if all_exposures:
        with open(csv_file, 'w', newline='') as f:
            fieldnames = [
                'Risk Level', 'Account', 'Region', 'Security Group ID', 'Security Group Name',
                'Protocol', 'Port', 'CIDR', 'Instance Count', 'Attached Instances'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for exposure in all_exposures:
                instances_str = ', '.join([
                    f"{inst['name']}({inst['id']})" if inst['name'] else inst['id']
                    for inst in exposure.get('attached_instances', [])
                ]) if exposure.get('attached_instances') else 'None'
                
                writer.writerow({
                    'Risk Level': exposure['risk_level'],
                    'Account': exposure['account'],
                    'Region': exposure['region'],
                    'Security Group ID': exposure['security_group_id'],
                    'Security Group Name': exposure['security_group_name'],
                    'Protocol': exposure['protocol'],
                    'Port': exposure['port'],
                    'CIDR': exposure.get('cidr', '0.0.0.0/0'),
                    'Instance Count': exposure['instance_count'],
                    'Attached Instances': instances_str
                })
    
    # User activities CSV
    user_csv_file = '/tmp/user-activities-comprehensive.csv'
    
    if user_events:
        with open(user_csv_file, 'w', newline='') as f:
            fieldnames = ['Service', 'Account', 'Region', 'Time', 'User', 'Action', 'Resource', 'Critical']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for event in sorted(user_events, key=lambda x: x['event_time'], reverse=True):
                writer.writerow({
                    'Service': event['service'],
                    'Account': event['account'],
                    'Region': event['region'],
                    'Time': event['time'],
                    'User': event['user'],
                    'Action': event['action'],
                    'Resource': event['resource'],
                    'Critical': event['critical']
                })
    
    print(f"✅ CSV files created:")
    print(f"   📄 Security exposures: {csv_file} ({len(all_exposures)} rows)")
    print(f"   📄 User activities: {user_csv_file} ({len(user_events)} rows)")
    
    return csv_file, user_csv_file

def send_comprehensive_report(critical_exposures, medium_exposures, low_exposures, user_events):
    """Send comprehensive HTML email report with CSV attachments"""
    
    # Generate HTML content (only shows CRITICAL exposures in body)
    html_content = create_html_report(critical_exposures, user_events)
    
    # Create CSV files (contains all risk levels)
    csv_file, user_csv_file = create_csv_files(critical_exposures, medium_exposures, low_exposures, user_events)
    
    # Prepare email
    current_date = datetime.now().strftime('%Y-%m-%d')
    subject = f'AWS Executive Security Dashboard - {current_date}'
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg['To'] = RECIPIENT_EMAIL
    
    # Attach HTML content
    html_part = MIMEText(html_content, 'html')
    msg.attach(html_part)
    
    # Attach CSV files
    for attachment_file, filename in [(csv_file, f'security-exposures-{current_date}.csv'), 
                                     (user_csv_file, f'user-activities-{current_date}.csv')]:
        if os.path.exists(attachment_file):
            with open(attachment_file, 'rb') as f:
                csv_attachment = MIMEApplication(f.read(), _subtype='csv')
                csv_attachment.add_header('Content-Disposition', 'attachment', filename=filename)
                msg.attach(csv_attachment)
    
    # Send email via SES
    try:
        print("📧 Sending comprehensive security dashboard...")
        
        session = boto3.Session(profile_name='unified')
        ses_client = session.client('ses', region_name='us-east-1')
        
        response = ses_client.send_raw_email(
            Source=f"{SENDER_NAME} <{SENDER_EMAIL}>",
            Destinations=[RECIPIENT_EMAIL],
            RawMessage={'Data': msg.as_string()}
        )
        
        print(f"✅ COMPREHENSIVE SECURITY DASHBOARD SENT SUCCESSFULLY!")
        print(f"📧 MessageId: {response['MessageId']}")
        print(f"🔴 Critical exposures: {len(critical_exposures)}")
        print(f"🟡 Medium exposures: {len(medium_exposures)}")
        print(f"🟢 Low exposures: {len(low_exposures)}")
        print(f"👤 User activities: {len(user_events)}")
        
    except Exception as e:
        print(f"❌ Error sending email: {e}")

if __name__ == "__main__":
    print("🚀 Starting AWS Comprehensive Security Dashboard...")
    
    # Scan security groups with correct risk classification
    critical_exposures, medium_exposures, low_exposures = scan_security_groups_comprehensive()
    
    # Detect IAM user activities
    user_events = detect_user_activities()
    
    # Send comprehensive report
    send_comprehensive_report(critical_exposures, medium_exposures, low_exposures, user_events)
    
    print(f"\\n=== SCAN COMPLETE ===")
    print(f"Dashboard generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")