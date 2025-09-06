# AWS Security Assessment with Boto3

A comprehensive guide for enumerating AWS resources using Boto3, the AWS SDK for Python, for security assessments and penetration testing.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Authentication Setup](#authentication-setup)
- [Basic Enumeration Script](#basic-enumeration-script)
- [Advanced Enumeration](#advanced-enumeration)
- [Security Considerations](#security-considerations)
- [Modern Security Tools](#modern-security-tools)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Python 3.7 or higher
- Valid AWS credentials with appropriate permissions
- Basic understanding of AWS services and IAM
- Proper authorization for security assessment activities

## Installation

Install the required dependencies:

```bash
pip3 install boto3 botocore
```

For enhanced functionality, consider installing additional packages:

```bash
pip3 install boto3 botocore tabulate colorama
```

## Authentication Setup

### Method 1: AWS Credentials File
```bash
aws configure
```

### Method 2: Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

### Method 3: IAM Roles (Recommended for EC2)
```python
import boto3

# Automatically uses IAM role attached to EC2 instance
session = boto3.Session()
```

## Basic Enumeration Script

Here's an enhanced script that enumerates multiple AWS services with proper error handling:

```python
#!/usr/bin/env python3
"""
AWS Security Assessment Enumeration Script
Author: Security Team
Purpose: Enumerate AWS resources for security assessment
"""

import boto3
import json
import sys
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from tabulate import tabulate
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('aws_enumeration.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class AWSEnumerator:
    def __init__(self, region_name='us-east-1', profile_name=None):
        """Initialize AWS session with error handling"""
        try:
            if profile_name:
                self.session = boto3.Session(profile_name=profile_name, region_name=region_name)
            else:
                self.session = boto3.Session(region_name=region_name)
            
            # Test credentials
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()
            logging.info(f"Authenticated as: {identity.get('Arn', 'Unknown')}")
            
        except (NoCredentialsError, PartialCredentialsError) as e:
            logging.error(f"Credential error: {e}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Session initialization error: {e}")
            sys.exit(1)

    def enumerate_ec2_instances(self):
        """Enumerate EC2 instances with pagination support"""
        try:
            ec2_client = self.session.client('ec2')
            paginator = ec2_client.get_paginator('describe_instances')
            
            instances = []
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instances.append({
                            'InstanceId': instance['InstanceId'],
                            'State': instance['State']['Name'],
                            'InstanceType': instance['InstanceType'],
                            'LaunchTime': instance.get('LaunchTime', 'N/A'),
                            'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                            'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A')
                        })
            
            if instances:
                print("\n" + "="*50)
                print("EC2 INSTANCES")
                print("="*50)
                print(tabulate(instances, headers="keys", tablefmt="grid"))
            else:
                print("\nNo EC2 instances found.")
                
            return instances
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UnauthorizedOperation':
                logging.warning("Insufficient permissions to enumerate EC2 instances")
            else:
                logging.error(f"EC2 enumeration error: {e}")
            return []

    def enumerate_s3_buckets(self):
        """Enumerate S3 buckets and their configurations"""
        try:
            s3_client = self.session.client('s3')
            buckets_response = s3_client.list_buckets()
            
            buckets = []
            for bucket in buckets_response['Buckets']:
                bucket_info = {
                    'Name': bucket['Name'],
                    'CreationDate': bucket['CreationDate'],
                    'Region': 'Unknown',
                    'PublicAccess': 'Unknown'
                }
                
                # Get bucket region
                try:
                    location = s3_client.get_bucket_location(Bucket=bucket['Name'])
                    bucket_info['Region'] = location.get('LocationConstraint', 'us-east-1')
                except ClientError:
                    pass
                
                # Check public access block
                try:
                    public_access = s3_client.get_public_access_block(Bucket=bucket['Name'])
                    bucket_info['PublicAccess'] = 'Blocked' if public_access else 'Not Blocked'
                except ClientError:
                    bucket_info['PublicAccess'] = 'Not Configured'
                
                buckets.append(bucket_info)
            
            if buckets:
                print("\n" + "="*50)
                print("S3 BUCKETS")
                print("="*50)
                print(tabulate(buckets, headers="keys", tablefmt="grid"))
            else:
                print("\nNo S3 buckets found.")
                
            return buckets
            
        except ClientError as e:
            logging.error(f"S3 enumeration error: {e}")
            return []

    def enumerate_iam_resources(self):
        """Enumerate IAM users, roles, and policies"""
        try:
            iam_client = self.session.client('iam')
            
            # Enumerate IAM Users
            users_paginator = iam_client.get_paginator('list_users')
            users = []
            for page in users_paginator.paginate():
                for user in page['Users']:
                    users.append({
                        'UserName': user['UserName'],
                        'CreateDate': user['CreateDate'],
                        'Arn': user['Arn']
                    })
            
            # Enumerate IAM Roles
            roles_paginator = iam_client.get_paginator('list_roles')
            roles = []
            for page in roles_paginator.paginate():
                for role in page['Roles']:
                    roles.append({
                        'RoleName': role['RoleName'],
                        'CreateDate': role['CreateDate'],
                        'Arn': role['Arn']
                    })
            
            if users:
                print("\n" + "="*50)
                print("IAM USERS")
                print("="*50)
                print(tabulate(users, headers="keys", tablefmt="grid"))
            
            if roles:
                print("\n" + "="*50)
                print("IAM ROLES")
                print("="*50)
                print(tabulate(roles, headers="keys", tablefmt="grid"))
                
            return {'users': users, 'roles': roles}
            
        except ClientError as e:
            logging.error(f"IAM enumeration error: {e}")
            return {'users': [], 'roles': []}

    def enumerate_lambda_functions(self):
        """Enumerate Lambda functions"""
        try:
            lambda_client = self.session.client('lambda')
            paginator = lambda_client.get_paginator('list_functions')
            
            functions = []
            for page in paginator.paginate():
                for function in page['Functions']:
                    functions.append({
                        'FunctionName': function['FunctionName'],
                        'Runtime': function.get('Runtime', 'N/A'),
                        'LastModified': function['LastModified'],
                        'CodeSize': function['CodeSize'],
                        'Role': function['Role']
                    })
            
            if functions:
                print("\n" + "="*50)
                print("LAMBDA FUNCTIONS")
                print("="*50)
                print(tabulate(functions, headers="keys", tablefmt="grid"))
            else:
                print("\nNo Lambda functions found.")
                
            return functions
            
        except ClientError as e:
            logging.error(f"Lambda enumeration error: {e}")
            return []

    def enumerate_rds_instances(self):
        """Enumerate RDS database instances"""
        try:
            rds_client = self.session.client('rds')
            paginator = rds_client.get_paginator('describe_db_instances')
            
            instances = []
            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    instances.append({
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'Engine': instance['Engine'],
                        'DBInstanceStatus': instance['DBInstanceStatus'],
                        'AllocatedStorage': instance.get('AllocatedStorage', 'N/A'),
                        'PubliclyAccessible': instance.get('PubliclyAccessible', False)
                    })
            
            if instances:
                print("\n" + "="*50)
                print("RDS INSTANCES")
                print("="*50)
                print(tabulate(instances, headers="keys", tablefmt="grid"))
            else:
                print("\nNo RDS instances found.")
                
            return instances
            
        except ClientError as e:
            logging.error(f"RDS enumeration error: {e}")
            return []

    def enumerate_cloudtrail(self):
        """Enumerate CloudTrail configurations"""
        try:
            cloudtrail_client = self.session.client('cloudtrail')
            trails = cloudtrail_client.describe_trails()
            
            trail_info = []
            for trail in trails['trailList']:
                trail_info.append({
                    'Name': trail['Name'],
                    'S3BucketName': trail.get('S3BucketName', 'N/A'),
                    'IsMultiRegionTrail': trail.get('IsMultiRegionTrail', False),
                    'IsLogging': 'Unknown'
                })
                
                # Check if trail is logging
                try:
                    status = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
                    trail_info[-1]['IsLogging'] = status.get('IsLogging', False)
                except ClientError:
                    pass
            
            if trail_info:
                print("\n" + "="*50)
                print("CLOUDTRAIL CONFIGURATIONS")
                print("="*50)
                print(tabulate(trail_info, headers="keys", tablefmt="grid"))
            else:
                print("\nNo CloudTrail configurations found.")
                
            return trail_info
            
        except ClientError as e:
            logging.error(f"CloudTrail enumeration error: {e}")
            return []

    def enumerate_security_groups(self):
        """Enumerate VPC Security Groups"""
        try:
            ec2_client = self.session.client('ec2')
            paginator = ec2_client.get_paginator('describe_security_groups')
            
            security_groups = []
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    # Check for overly permissive rules
                    risky_rules = []
                    for rule in sg.get('IpPermissions', []):
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                risky_rules.append(f"Port {rule.get('FromPort', 'All')}")
                    
                    security_groups.append({
                        'GroupId': sg['GroupId'],
                        'GroupName': sg['GroupName'],
                        'VpcId': sg.get('VpcId', 'Classic'),
                        'RiskyRules': ', '.join(risky_rules) if risky_rules else 'None'
                    })
            
            if security_groups:
                print("\n" + "="*50)
                print("SECURITY GROUPS")
                print("="*50)
                print(tabulate(security_groups, headers="keys", tablefmt="grid"))
                
            return security_groups
            
        except ClientError as e:
            logging.error(f"Security Groups enumeration error: {e}")
            return []

    def run_full_enumeration(self):
        """Run complete AWS enumeration"""
        print("Starting AWS Security Assessment Enumeration...")
        print("=" * 60)
        
        results = {
            'ec2_instances': self.enumerate_ec2_instances(),
            's3_buckets': self.enumerate_s3_buckets(),
            'iam_resources': self.enumerate_iam_resources(),
            'lambda_functions': self.enumerate_lambda_functions(),
            'rds_instances': self.enumerate_rds_instances(),
            'cloudtrail': self.enumerate_cloudtrail(),
            'security_groups': self.enumerate_security_groups()
        }
        
        # Save results to JSON file
        with open('aws_enumeration_results.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n{'='*60}")
        print("Enumeration completed. Results saved to aws_enumeration_results.json")
        print("Log file: aws_enumeration.log")
        
        return results

def main():
    """Main function with argument parsing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS Security Assessment Enumeration')
    parser.add_argument('--region', default='us-east-1', help='AWS region (default: us-east-1)')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--service', choices=['ec2', 's3', 'iam', 'lambda', 'rds', 'cloudtrail', 'sg'], 
                       help='Enumerate specific service only')
    
    args = parser.parse_args()
    
    # Initialize enumerator
    enumerator = AWSEnumerator(region_name=args.region, profile_name=args.profile)
    
    # Run specific service enumeration or full enumeration
    if args.service:
        service_methods = {
            'ec2': enumerator.enumerate_ec2_instances,
            's3': enumerator.enumerate_s3_buckets,
            'iam': enumerator.enumerate_iam_resources,
            'lambda': enumerator.enumerate_lambda_functions,
            'rds': enumerator.enumerate_rds_instances,
            'cloudtrail': enumerator.enumerate_cloudtrail,
            'sg': enumerator.enumerate_security_groups
        }
        service_methods[args.service]()
    else:
        enumerator.run_full_enumeration()

if __name__ == "__main__":
    main()
```

## Advanced Enumeration

### Multi-Region Enumeration

```python
def enumerate_all_regions():
    """Enumerate resources across all AWS regions"""
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    
    all_results = {}
    for region in regions:
        print(f"\nEnumerating region: {region}")
        enumerator = AWSEnumerator(region_name=region)
        all_results[region] = enumerator.run_full_enumeration()
    
    return all_results
```

### Credential Enumeration

```python
def check_credentials_exposure():
    """Check for exposed credentials in various AWS services"""
    # Check EC2 user data
    # Check Lambda environment variables
    # Check ECS task definitions
    # Check Systems Manager parameters
    pass
```

## Security Considerations

### Required IAM Permissions

For comprehensive enumeration, the following IAM permissions are recommended:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetPublicAccessBlock",
                "iam:List*",
                "iam:Get*",
                "lambda:ListFunctions",
                "rds:Describe*",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

### Ethical Guidelines

- **Authorization Required**: Always ensure you have explicit written permission before conducting security assessments
- **Scope Limitations**: Stay within the defined scope of your assessment
- **Data Handling**: Follow proper data handling procedures for any discovered sensitive information
- **Rate Limiting**: Implement appropriate delays to avoid overwhelming AWS APIs
- **Logging**: Maintain detailed logs of all enumeration activities

## Modern Security Tools

While this script provides a foundation, consider using specialized AWS security tools:

### ScoutSuite
```bash
pip install scoutsuite
scout aws
```

### Prowler
```bash
git clone https://github.com/prowler-cloud/prowler
cd prowler
./prowler aws
```

### Pacu
```bash
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu
python3 pacu.py
```

### CloudMapper
```bash
git clone https://github.com/duo-labs/cloudmapper.git
cd cloudmapper
pip install -r requirements.txt
```

## Best Practices

1. **Use IAM Roles**: Prefer IAM roles over access keys when possible
2. **Implement MFA**: Use multi-factor authentication for sensitive operations
3. **Rotate Credentials**: Regularly rotate access keys and credentials
4. **Monitor API Calls**: Use CloudTrail to monitor enumeration activities
5. **Least Privilege**: Use minimal required permissions for enumeration
6. **Error Handling**: Always implement proper error handling and logging
7. **Rate Limiting**: Respect AWS API rate limits to avoid throttling

## Troubleshooting

### Common Issues

1. **Credential Errors**
   ```
   NoCredentialsError: Unable to locate credentials
   ```
   Solution: Configure AWS credentials using `aws configure` or environment variables

2. **Permission Denied**
   ```
   ClientError: An error occurred (UnauthorizedOperation)
   ```
   Solution: Ensure your IAM user/role has the necessary permissions

3. **Region Issues**
   ```
   EndpointConnectionError: Could not connect to the endpoint URL
   ```
   Solution: Verify the region name and ensure the service is available in that region

4. **Rate Limiting**
   ```
   ClientError: An error occurred (Throttling)
   ```
   Solution: Implement exponential backoff and retry logic

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
boto3.set_stream_logger('boto3', logging.DEBUG)
```

## Additional Resources

- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [Boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [AWS CLI Configuration](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
- [OWASP Cloud Security Testing Guide](https://owasp.org/www-project-cloud-security-testing-guide/)

---

**Disclaimer**: This guide is intended for authorized security assessments only. Always ensure you have proper authorization before conducting any security testing activities. Unauthorized access to AWS resources is illegal and may result in criminal charges.