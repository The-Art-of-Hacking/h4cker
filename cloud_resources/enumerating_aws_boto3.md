# Using Boto3, the AWS SDK for Python, to enumerate EC2 instances
The following is a simple script using Boto3, the AWS SDK for Python, to enumerate EC2 instances, S3 buckets, and IAM roles. This script assumes that you have the necessary permissions and that your AWS credentials are properly configured.

```python
import boto3

# Create a session using your AWS credentials
session = boto3.Session()

# Enumerate EC2 Instances
print("EC2 Instances:")
ec2_client = session.client('ec2')
instances = ec2_client.describe_instances()
for reservation in instances['Reservations']:
    for instance in reservation['Instances']:
        print(f"ID: {instance['InstanceId']}, State: {instance['State']['Name']}, Type: {instance['InstanceType']}")

# Enumerate S3 Buckets
print("\nS3 Buckets:")
s3_client = session.client('s3')
buckets = s3_client.list_buckets()
for bucket in buckets['Buckets']:
    print(f"Name: {bucket['Name']}")

# Enumerate IAM Roles
print("\nIAM Roles:")
iam_client = session.client('iam')
roles = iam_client.list_roles()
for role in roles['Roles']:
    print(f"Name: {role['RoleName']}, ARN: {role['Arn']}")

```

This script will print the details of EC2 instances, S3 buckets, and IAM roles in your AWS account.

### Important Considerations:
- **Permissions:** Make sure the AWS credentials you're using have the necessary permissions to list EC2 instances, S3 buckets, and IAM roles.
- **Region:** By default, the script will use the region specified in your AWS configuration. If you want to specify a different region, you can do so when creating the session (e.g., `session = boto3.Session(region_name='us-west-2')`).
- **Ethical Considerations:** Ensure that you have proper authorization to run this script on the target AWS account, as unauthorized scanning or enumeration can lead to legal issues.

Before running the script, you'll need to have Boto3 installed in your environment, which you can do with the following command:

```bash
pip3 install boto3
```

Once you have Boto3 installed and your AWS credentials configured, you can run the script to enumerate the specified resources.
