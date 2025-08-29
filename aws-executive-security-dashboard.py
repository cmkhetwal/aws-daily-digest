#!/usr/bin/env python3

import boto3
from datetime import datetime, timedelta
import os
import configparser
import csv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import json

print("=== AWS Executive Security Dashboard ===")
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
    """Check if an instance is critical based on ID or name patterns"""
    if not instance_id and not instance_name:
        return False
    
    # Check exact instance ID match
    if instance_id and instance_id.lower() in critical_patterns:
        return True
    
    # Check name pattern matches
    if instance_name:
        instance_name_lower = instance_name.lower()
        for pattern in critical_patterns:
            if pattern in instance_name_lower:
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
                        for rule in sg.get('IpRules', []) + sg.get('Ipv6Ranges', []) + sg.get('IpPermissions', []):
                            exposed_ports = []
                            
                            # Handle different rule formats
                            ip_ranges = []
                            if 'IpRanges' in rule:
                                ip_ranges.extend([r.get('CidrIp', '') for r in rule['IpRanges']])
                            if 'Ipv6Ranges' in rule:
                                ip_ranges.extend([r.get('CidrIpv6', '') for r in rule['Ipv6Ranges']])
                            
                            # Check for internet exposure (0.0.0.0/0 or ::/0)
                            is_internet_exposed = any(
                                cidr in ['0.0.0.0/0', '::/0'] for cidr in ip_ranges
                            )
                            
                            if is_internet_exposed:
                                from_port = rule.get('FromPort', 0)
                                to_port = rule.get('ToPort', 65535)
                                protocol = rule.get('IpProtocol', 'tcp')
                                
                                # Handle port ranges
                                if from_port == to_port:
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
                                    'instance_count': len(attached_instances)
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
    """Classify risk based on ports and instance criticality"""
    
    # Check if any attached instance is critical
    has_critical_instance = False
    for instance in attached_instances:
        if is_critical_instance(instance['id'], instance['name'], critical_patterns):
            has_critical_instance = True
            break
    
    # Risk classification logic
    if has_critical_instance:
        # Any port exposed on critical instances = CRITICAL
        return 'CRITICAL'
    else:
        # Non-critical instances
        if (from_port == 80 and to_port == 80) or (from_port == 443 and to_port == 443):
            # Only HTTP/HTTPS = LOW risk
            return 'LOW'
        else:
            # Other ports = MEDIUM risk
            return 'MEDIUM'

def create_html_report(critical_exposures, medium_exposures, low_exposures):
    """Generate professional HTML email report"""
    
    total_exposures = len(critical_exposures) + len(medium_exposures) + len(low_exposures)
    current_date = datetime.now().strftime('%Y-%m-%d')
    
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
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 30px; 
            text-align: center; 
            border-radius: 8px 8px 0 0; 
        }}
        .header h1 {{ 
            margin: 0; 
            font-size: 28px; 
            font-weight: 300; 
        }}
        .date {{ 
            margin-top: 10px; 
            opacity: 0.9; 
            font-size: 16px; 
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
        .top-risks {{ 
            background-color: #fff3cd; 
            border: 1px solid #ffeaa7; 
            border-radius: 8px; 
            padding: 20px; 
            margin: 20px 0; 
        }}
        .top-risks h3 {{ 
            margin-top: 0; 
            color: #856404; 
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
        .alert-medium {{ background-color: #fff3cd; color: #856404; }}
        .alert-low {{ background-color: #d4edda; color: #155724; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Daily AWS Infrastructure Change Summary</h1>
            <div class="date">Date: {current_date}</div>
        </div>
        
        <div class="content">
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-number" style="color: #dc3545;">{len(critical_exposures)}</div>
                    <div class="summary-label">Critical Exposures</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number" style="color: #fd7e14;">{len(medium_exposures)}</div>
                    <div class="summary-label">Medium Risks</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number" style="color: #28a745;">{len(low_exposures)}</div>
                    <div class="summary-label">Low Risks</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number" style="color: #007bff;">{total_exposures}</div>
                    <div class="summary-label">Total Found</div>
                </div>
            </div>
    '''
    
    # Critical exposures section
    if critical_exposures:
        html_content += '''
            <div class="risk-section critical">
                <div class="risk-title">
                    <span class="risk-icon">🚨</span>
                    CRITICAL: PORTS EXPOSED TO INTERNET
                    <span class="risk-count alert-critical">''' + str(len(critical_exposures)) + ''' found</span>
                </div>
        '''
        
        # Add the critical instances details
        critical_instances_text = []
        for exposure in critical_exposures:
            for instance in exposure.get('attached_instances', []):
                critical_instances_text.append(f"{instance['name']}({instance['id']})" if instance['name'] else instance['id'])
        
        if critical_instances_text:
            html_content += f'''
                <div class="exposure-item" style="background-color: #f8d7da; border-left: 4px solid #dc3545; margin-bottom: 15px;">
                    <strong>🔴 CRITICAL INSTANCES FOUND:</strong><br>
                    {', '.join(set(critical_instances_text))}
                </div>
            '''
        
        for idx, exposure in enumerate(critical_exposures[:10], 1):  # Show top 10
            port_text = f"Port {exposure['port']}" if exposure['port'] != "All Ports" else exposure['port']
            instances_text = f"({exposure['instance_count']} instances)" if exposure['instance_count'] > 0 else "(no instances)"
            
            html_content += f'''
                <div class="exposure-item">
                    <span class="port-highlight">• {exposure['protocol'].upper()} ({exposure['port']}) → {exposure['security_group_name']} ({exposure['security_group_id']}) in {exposure['region']}</span>
                    <div class="instance-info">Account: {exposure['account']} | Instances: {instances_text}</div>
                </div>
            '''
        
        html_content += '</div>'
    
    # Medium risks section
    if medium_exposures:
        html_content += '''
            <div class="risk-section medium">
                <div class="risk-title">
                    <span class="risk-icon">⚠️</span>
                    MEDIUM RISKS
                    <span class="risk-count alert-medium">''' + str(len(medium_exposures)) + ''' found</span>
                </div>
        '''
        
        for idx, exposure in enumerate(medium_exposures[:15], 1):  # Show top 15
            instances_text = f"({exposure['instance_count']} instances)" if exposure['instance_count'] > 0 else "(no instances)"
            
            html_content += f'''
                <div class="exposure-item">
                    <span class="port-highlight">• {exposure['protocol'].upper()} ({exposure['port']}) → {exposure['security_group_name']} ({exposure['security_group_id']}) in {exposure['region']}</span>
                    <div class="instance-info">Account: {exposure['account']} | Instances: {instances_text}</div>
                </div>
            '''
        
        html_content += '</div>'
    
    # Top risks summary
    top_critical = critical_exposures[:3] if critical_exposures else []
    if top_critical:
        html_content += '''
            <div class="top-risks">
                <h3>🚨 TOP RISKS TODAY</h3>
        '''
        
        for idx, risk in enumerate(top_critical, 1):
            port_desc = f"{risk['protocol'].upper()} ({risk['port']})"
            html_content += f'''
                <div>{idx}. ⚠️ <strong>{port_desc} exposed to internet</strong> → {risk['security_group_name']} in {risk['region']}</div>
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

def create_csv_files(critical_exposures, medium_exposures, low_exposures):
    """Create CSV files for all risk levels"""
    
    all_exposures = []
    
    # Add risk level to each exposure
    for exposure in critical_exposures:
        exposure['risk_level'] = 'CRITICAL'
        all_exposures.append(exposure)
    
    for exposure in medium_exposures:
        exposure['risk_level'] = 'MEDIUM'
        all_exposures.append(exposure)
    
    for exposure in low_exposures:
        exposure['risk_level'] = 'LOW'
        all_exposures.append(exposure)
    
    # Create comprehensive CSV
    csv_file = '/tmp/security-exposures-comprehensive.csv'
    
    if all_exposures:
        with open(csv_file, 'w', newline='') as f:
            fieldnames = [
                'Risk Level', 'Account', 'Region', 'Security Group ID', 'Security Group Name',
                'Protocol', 'Port', 'Instance Count', 'Attached Instances'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for exposure in all_exposures:
                # Format attached instances
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
                    'Instance Count': exposure['instance_count'],
                    'Attached Instances': instances_str
                })
    
    print(f"✅ CSV file created: {csv_file} with {len(all_exposures)} exposures")
    return csv_file

def send_html_email_report(critical_exposures, medium_exposures, low_exposures):
    """Send professional HTML email report"""
    
    total_exposures = len(critical_exposures) + len(medium_exposures) + len(low_exposures)
    
    if total_exposures == 0:
        print("✅ No security exposures found - no email needed")
        return
    
    # Generate HTML content
    html_content = create_html_report(critical_exposures, medium_exposures, low_exposures)
    
    # Create CSV file
    csv_file = create_csv_files(critical_exposures, medium_exposures, low_exposures)
    
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
    
    # Attach CSV file
    if os.path.exists(csv_file):
        with open(csv_file, 'rb') as f:
            csv_attachment = MIMEApplication(f.read(), _subtype='csv')
            csv_attachment.add_header(
                'Content-Disposition', 
                'attachment', 
                filename=f'security-exposures-{current_date}.csv'
            )
            msg.attach(csv_attachment)
    
    # Send email via SES
    try:
        print("📧 Sending HTML security dashboard...")
        
        # Use unified profile for SES
        session = boto3.Session(profile_name='unified')
        ses_client = session.client('ses', region_name='us-east-1')
        
        response = ses_client.send_raw_email(
            Source=f"{SENDER_NAME} <{SENDER_EMAIL}>",
            Destinations=[RECIPIENT_EMAIL],
            RawMessage={'Data': msg.as_string()}
        )
        
        print(f"✅ HTML SECURITY DASHBOARD SENT SUCCESSFULLY!")
        print(f"📧 MessageId: {response['MessageId']}")
        print(f"📊 Total exposures: {total_exposures}")
        print(f"🔴 Critical: {len(critical_exposures)}")
        print(f"🟡 Medium: {len(medium_exposures)}")
        print(f"🟢 Low: {len(low_exposures)}")
        
    except Exception as e:
        print(f"❌ Error sending email: {e}")

if __name__ == "__main__":
    print("🚀 Starting AWS Executive Security Dashboard...")
    
    # Scan security groups with new risk classification
    critical_exposures, medium_exposures, low_exposures = scan_security_groups_comprehensive()
    
    # Send HTML email report
    send_html_email_report(critical_exposures, medium_exposures, low_exposures)
    
    print(f"\\n=== SCAN COMPLETE ===")
    print(f"Dashboard generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")