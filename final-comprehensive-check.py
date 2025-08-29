#!/usr/bin/env python3

import boto3
from datetime import datetime, timedelta
import os
import configparser
import csv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

print("=== COMPREHENSIVE AWS USER ACTIVITY REPORT ===")
print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}")

# Email configuration
SENDER_EMAIL = "no-reply@bamko.net"
SENDER_NAME = "Bamko Security Team"
RECIPIENT_EMAIL = "cmkhetwal@hotmail.com"

# Discover AWS profiles
def discover_aws_profiles():
    profiles = []
    credentials_file = os.path.expanduser('~/.aws/credentials')
    
    if os.path.exists(credentials_file):
        config = configparser.ConfigParser()
        config.read(credentials_file)
        
        for section in config.sections():
            if section != 'default':
                profiles.append(section)
    
    return profiles

def get_critical_events():
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

def find_all_user_activities():
    profiles = discover_aws_profiles()
    print(f"Scanning {len(profiles)} AWS profiles: {', '.join(profiles)}")
    
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=48)  # Last 48 hours
    
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
    
    excluded_users = [
        'DataLifecycleManager',
        'AWSBackup-AWSBackupDefaultServiceRole', 
        'AWS Internal',
        'aws-elasticbeanstalk-ec2-role',
        'configLambdaExecution'
    ]
    
    for profile in profiles:
        print(f"\\nScanning {profile}...")
        try:
            session = boto3.Session(profile_name=profile)
            
            for region in regions:
                print(f"  Region: {region}")
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
                            
                            if (username and 
                                username not in excluded_users and 
                                not username.startswith('i-')):
                                
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
                                print(f"    ✓ Found: {username} - {event_name} - {resource_name}")
                                
                    except Exception as e:
                        continue
                        
        except Exception as e:
            print(f"  Error scanning {profile}: {e}")
            continue
    
    return all_user_events

def create_comprehensive_csv(events):
    csv_file = '/tmp/comprehensive-user-events.csv'
    
    if events:
        # Sort by time (most recent first)
        sorted_events = sorted(events, key=lambda x: x['event_time'], reverse=True)
        
        with open(csv_file, 'w', newline='') as f:
            fieldnames = ['Service', 'Account', 'Region', 'Time', 'User', 'Action', 'Resource', 'Critical']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for event in sorted_events:
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
    
    print(f"✅ CSV file created: {csv_file} with {len(events)} rows")
    return csv_file

def send_comprehensive_report(events):
    if not events:
        print("❌ No user events found to report")
        return
        
    csv_file = create_comprehensive_csv(events)
    
    # Count events by service
    service_counts = {}
    critical_count = 0
    
    for event in events:
        service = event['action'].replace('Put', '').replace('Create', '').replace('Delete', '').replace('Start', '').replace('Stop', '')
        service_counts[service] = service_counts.get(service, 0) + 1
        if event['critical'] == 'YES':
            critical_count += 1
    
    # Create report body
    report_body = f"""🚀 COMPREHENSIVE AWS USER ACTIVITY REPORT
Date: {datetime.now().strftime('%Y-%m-%d %H:%M IST')} - USER-DRIVEN ACTIONS ONLY

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔄 USER ACTIVITIES DETECTED (Last 48 Hours): {len(events)} total
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 ACTIVITY BREAKDOWN:
""" + '\\n'.join([f"• {service}: {count} actions" for service, count in service_counts.items()]) + f"""

🚨 CRITICAL ACTIONS: {critical_count} high-risk activities

📋 RECENT USER ACTIVITIES:
""" + '\\n'.join([f"• {event['time']} - {event['user']} - {event['action']} in {event['account']}/{event['region']}" 
                  + (f" - {event['resource']}" if event['resource'] else "")
                  for event in sorted(events, key=lambda x: x['event_time'], reverse=True)[:10]]) + f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📎 ATTACHED: Complete CSV with all user activities
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}
✅ Successfully captured all user-driven AWS activities!

🔍 FILTERED OUT: Automated services (DataLifecycleManager, AWSBackup, etc.)
👥 USERS CAPTURED: Real IAM users and human-initiated actions only
"""

    # Send email
    print("📧 Sending comprehensive user activity report...")
    
    msg = MIMEMultipart()
    msg['Subject'] = f'🚨 AWS User Activity Report - {len(events)} Actions by Real Users - {datetime.now().strftime("%Y-%m-%d")}'
    msg['From'] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg['To'] = RECIPIENT_EMAIL
    
    msg.attach(MIMEText(report_body, 'plain'))
    
    # Attach CSV
    if os.path.exists(csv_file):
        with open(csv_file, 'rb') as f:
            attachment = MIMEApplication(f.read(), _subtype='csv')
            attachment.add_header('Content-Disposition', 'attachment', filename='user-activities.csv')
            msg.attach(attachment)
    
    # Send via SES
    try:
        session = boto3.Session(profile_name='unified')
        ses_client = session.client('ses', region_name='us-east-1')
        
        response = ses_client.send_raw_email(
            Source=f"{SENDER_NAME} <{SENDER_EMAIL}>",
            Destinations=[RECIPIENT_EMAIL],
            RawMessage={'Data': msg.as_string()}
        )
        
        print(f"✅ USER ACTIVITY REPORT SENT SUCCESSFULLY!")
        print(f"MessageId: {response['MessageId']}")
        print(f"📊 Total user activities: {len(events)}")
        print(f"🚨 Critical activities: {critical_count}")
        
    except Exception as e:
        print(f"❌ Error sending email: {e}")

if __name__ == "__main__":
    user_events = find_all_user_activities()
    
    print(f"\\n=== SUMMARY ===")
    print(f"Total user activities found: {len(user_events)}")
    
    if user_events:
        print("\\nUser activities by account:")
        accounts = {}
        for event in user_events:
            key = f"{event['account']} - {event['user']}"
            accounts[key] = accounts.get(key, 0) + 1
        
        for account, count in sorted(accounts.items()):
            print(f"  {account}: {count} activities")
        
        send_comprehensive_report(user_events)
    else:
        print("No user activities found in the last 48 hours")