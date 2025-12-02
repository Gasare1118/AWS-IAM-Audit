# AWS-IAM-Audit

# Introduction
IAM misconfigurations remain one of the most common causes of breaches and often lead to massive data loss. Many organizations rely on default alerts or periodic batch scans, which means misconfigurations can go undetected for hours or even days. I am building an IAM Role Auditing System using AWS Lambda and Config to continuously monitor the IAM roles for misconfigurations and send alerts via SNS in real time whenever risky permissions are detected.

# Architecture
<img width="720" height="588" alt="image" src="https://github.com/user-attachments/assets/c4699aea-d18c-4804-aaa3-9cbaba87c263" />


AWS Config continuously monitors IAM roles and policies for configuration changes, storing snapshots in S3. When a change is detected, Config triggers the Lambda function with event details. Lambda queries IAM APIs to retrieve policy documents, analyzes them for wildcard permissions, and logs all activity to CloudWatch. If misconfigurations are found, Lambda publishes an alert to SNS, which sends email notifications to the security team.
Here is how I built the system: AWS Config continuously monitors and detects changes to IAM roles and policies. When a change occurs, Config triggers a Lambda function that analyzes the permissions for common misconfigurations (specifically wildcard actions and resources). If issues are found, Lambda publishes an alert to an SNS topic, which emails the security team AKA Me…lol.

# Services Used
There are four main AWS services that are being used to provide continuous monitoring for this project:

**AWS Config**: Monitors/records changes to IAM roles

**AWS Lambda**: Analyzes IAM policies for misconfigurations

**Amazon SNS**: Sends email alerts to security team.

**CloudWatch**: Stores execution logs of lambda function.

# Detection rules
The lambda function will be written to specifically check for:

1. **Wildcard Action: “Action”: “*”**

2. **Wildcard Resources: “Resource”: “*”**

These indicate overly permissive policies that violate the principle of least privilege.

# Implementation Steps
To start implementing this system, I will first work on setting up the SNS topic, Lambda Function next, followed by the Config Rule and IAM policies needed for these services to be able to talk to each other.

1. **Creating the SNS Topic**: The SNS topic creation is very straight forward. I started by creating the SNS topic. In the SNS console, I navigated to Topics and clicked Create Topic. Since I needed email notifications, I chose Standard (FIFO doesn’t support email subscriptions) and named it IAMRoleAudit2025.
<img width="720" height="355" alt="image" src="https://github.com/user-attachments/assets/c74e97fd-e74f-4fd3-aeff-d7bbff13d3ac" />


Everything else will be left at its default setting and created the topic.

<img width="720" height="296" alt="image" src="https://github.com/user-attachments/assets/0ccffcc3-4b26-443a-a201-4d2172d8e1b0" />


Successfully created my SNS Topic
Once the topic was created, I subscribed to the SNS topic. In the protocol, I selected “Email” and entered the email address I want to receive alerts at in the “endpoint” field and created the subscription.

<img width="720" height="312" alt="image" src="https://github.com/user-attachments/assets/cd1de247-6514-4888-96a8-489de5addd23" />


Immediately after the subscription was created, I received an email to the address I used requesting confirmation of the subscription. I noted down the ARN of the SNS topic in the email, it will be needed when creating the lambda function.

<img width="720" height="156" alt="image" src="https://github.com/user-attachments/assets/a17b9678-240a-4b2e-b000-08fa5a1334ec" />


I confirmed the subscription and was redirected to a confirmation page indicating that the subscription was successful.


2. **Create the lambda function**: Now that the SNS topic has been created, I can go ahead and create the lambda function to review the IAM roles to flag roles with overly broad permissions, thus, in the attached and or inline policies, the function will be looking for specifically “Action”: “*” and/or “Resource”: “*”

**Configuration**

>Name: IAMRoleAudit1

>Runtime: Python 3.13

>Timeout: 30 seconds

>Memory: 256 MB

>Handler: lambda_function.lambda_handler

Environment variables: SNS_TOPIC_ARN = The ARN of the SNS topic that was created.

I used an environment variable for the SNS Topic ARN rather than hardcoding it in the code. This makes the function more flexible and follows best practices for configuration management.

This is the logic of my lambda function below. I used the boto3 documentation to work my way through this code. After running into several issues, this is the version of code that works flawlessly. I noted down the ARN of the lambda function, this will be used in the setup of the Config rule.

```python
import json
import boto3
import os

# Initialize AWS clients
iam_client = boto3.client('iam')
sns_client = boto3.client('sns')

# Get SNS Topic ARN from environment variable
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

def lambda_handler(event, context):
    """Main handler triggered by AWS Config"""
    
    # Debug: Log the event structure
    print(f"Received event keys: {list(event.keys())}")
    
    # Parse the Config event - handle both direct and wrapped formats
    config_item = None
    
    # Check if invokingEvent exists (typical Config format)
    if 'invokingEvent' in event:
        print("Parsing invokingEvent...")
        invoking_event = json.loads(event['invokingEvent'])
        config_item = invoking_event.get('configurationItem')
    # Check if configurationItem is directly in event
    elif 'configurationItem' in event:
        print("Using direct configurationItem...")
        config_item = event['configurationItem']
    
    # Validate we have a config item
    if not config_item:
        print(f"ERROR: No configurationItem found in event: {json.dumps(event, default=str)}")
        return {
            'statusCode': 400,
            'error': 'No configurationItem in event'
        }
    
    # Get resource information
    resource_type = config_item.get('resourceType')
    resource_name = config_item.get('resourceName')
    
    if not resource_name:
        print("ERROR: No resourceName in configurationItem")
        return {
            'statusCode': 400,
            'error': 'No resource name found'
        }
    
    print(f"Analyzing resource: {resource_type} - {resource_name}")
    
    findings = []
    
    # Handle IAM Role changes
    if resource_type == 'AWS::IAM::Role':
        print(f"Processing IAM Role: {resource_name}")
        findings.extend(check_role(resource_name))
    
    # Handle IAM Policy changes
    elif resource_type == 'AWS::IAM::Policy':
        print(f"Processing IAM Policy: {resource_name}")
        findings.extend(check_policy(resource_name))
    
    else:
        print(f"Skipping unsupported resource type: {resource_type}")
        return {
            'statusCode': 200,
            'message': f'Skipped {resource_type}'
        }
    
    # Send alert if issues found
    if findings:
        send_sns_alert(resource_name, resource_type, findings)
        print(f"Alert sent for {resource_type}: {resource_name}")
    else:
        print(f"No issues found for {resource_type}: {resource_name}")
    
    return {
        'statusCode': 200,
        'resource': resource_name,
        'type': resource_type,
        'findings': findings
    }

def check_role(role_name):
    """Check policies attached to a role"""
    findings = []
    
    # Check attached customer-managed policies
    findings.extend(check_attached_policies(role_name))
    
    # Check inline policies
    findings.extend(check_inline_policies(role_name))
    
    return findings

def check_policy(policy_name):
    """Check a customer-managed policy and find which roles use it"""
    findings = []
    
    try:
        # Get the policy ARN - customer policies have account ID in ARN
        account_id = boto3.client('sts').get_caller_identity()['Account']
        policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
        
        # Check if this is an AWS-managed policy (skip if so)
        if policy_arn.startswith('arn:aws:iam::aws:policy/'):
            print(f"Skipping AWS-managed policy: {policy_name}")
            return findings
        
        print(f"Checking customer-managed policy: {policy_name}")
        
        # Get the policy document
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)
        default_version = policy_version['Policy']['DefaultVersionId']
        
        policy_doc = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version
        )
        
        # Check for wildcards
        document = policy_doc['PolicyVersion']['Document']
        policy_findings = scan_policy_for_wildcards(document, policy_name)
        
        if policy_findings:
            # Find which roles use this policy
            roles_using_policy = find_roles_using_policy(policy_arn)
            
            for finding in policy_findings:
                if roles_using_policy:
                    findings.append(f"{finding} (attached to roles: {', '.join(roles_using_policy)})")
                else:
                    findings.append(f"{finding} (not currently attached to any roles)")
        
    except Exception as e:
        print(f"Error checking policy: {str(e)}")
    
    return findings

def find_roles_using_policy(policy_arn):
    """Find all roles that have this policy attached"""
    roles = []
    
    try:
        # Get all roles
        paginator = iam_client.get_paginator('list_roles')
        
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName']
                
                # Check if this role has the policy attached
                attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                
                for policy in attached_policies['AttachedPolicies']:
                    if policy['PolicyArn'] == policy_arn:
                        roles.append(role_name)
                        break
    
    except Exception as e:
        print(f"Error finding roles using policy: {str(e)}")
    
    return roles

def check_attached_policies(role_name):
    """Check customer-managed policies attached to the role (skips AWS-managed)"""
    issues = []
    
    try:
        # Get list of attached policies
        response = iam_client.list_attached_role_policies(RoleName=role_name)
        
        for policy in response['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            policy_name = policy['PolicyName']
            
            # Skip AWS-managed policies - only check customer-managed
            if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                print(f"Skipping AWS-managed policy: {policy_name}")
                continue
            
            print(f"Checking customer-managed policy: {policy_name}")
            
            # Get the policy document
            policy_version = iam_client.get_policy(PolicyArn=policy_arn)
            default_version = policy_version['Policy']['DefaultVersionId']
            
            policy_doc = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version
            )
            
            # Check for wildcards
            document = policy_doc['PolicyVersion']['Document']
            issues.extend(scan_policy_for_wildcards(document, policy_name))
    
    except Exception as e:
        print(f"Error checking attached policies: {str(e)}")
    
    return issues

def check_inline_policies(role_name):
    """Check inline policies on the role (always custom)"""
    issues = []
    
    try:
        # Get list of inline policy names
        response = iam_client.list_role_policies(RoleName=role_name)
        
        for policy_name in response['PolicyNames']:
            print(f"Checking inline policy: {policy_name}")
            
            # Get the policy document
            policy_doc = iam_client.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )
            
            # Check for wildcards
            document = policy_doc['PolicyDocument']
            issues.extend(scan_policy_for_wildcards(document, policy_name))
    
    except Exception as e:
        print(f"Error checking inline policies: {str(e)}")
    
    return issues

def scan_policy_for_wildcards(policy_document, policy_name):
    """Scan a policy document for wildcard actions or resources"""
    findings = []
    
    statements = policy_document.get('Statement', [])
    
    for statement in statements:
        # Check Action field
        actions = statement.get('Action', [])
        if actions == '*' or (isinstance(actions, list) and '*' in actions):
            findings.append(f"Wildcard action found in policy '{policy_name}'")
        
        # Check Resource field
        resources = statement.get('Resource', [])
        if resources == '*' or (isinstance(resources, list) and '*' in resources):
            findings.append(f"Wildcard resource found in policy '{policy_name}'")
    
    return findings

def send_sns_alert(resource_name, resource_type, findings):
    """Send alert via SNS"""
    
    resource_label = "Role" if resource_type == "AWS::IAM::Role" else "Policy"
    
    message = f"""
IAM {resource_label.upper()} MISCONFIGURATION DETECTED

{resource_label}: {resource_name}

Issues Found:
{chr(10).join(findings)}

Action Required:
Review this {resource_label.lower()} and apply the principle of least privilege by replacing wildcard permissions with specific actions and resources.

Note: This alert only covers customer-managed and inline policies. AWS-managed policies are not flagged.
    """
    
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"IAM Alert: Misconfigured {resource_label} '{resource_name}'",
            Message=message
        )
        print(f"SNS alert sent successfully to {SNS_TOPIC_ARN}")
    except Exception as e:
        print(f"Error sending SNS alert: {str(e)}")
```
3. **Create the Custom Config Rule**: Now that my lambda function has been created, I can move on with creating my config rule to trigger the lambda function. On the Config rules page, I added a new “Custom Lambda rule” and named it IAMRoleAudit1-Rule and I entered the ARN of the lambda function I previously created.

<img width="720" height="221" alt="image" src="https://github.com/user-attachments/assets/5b56448a-58d4-4ec4-8f1e-d5fb26a11ba9" />


I set the evaluation mode to detective evaluation, and set the trigger type to run when configuration changes. In the scope of changes, I selected Resources, selecting resources allows me specify which resources I want config to monitor changes for and trigger the Lambda function based on that. In the resource type, I selected AWS IAM Role and AWS IAM Policy.

<img width="720" height="331" alt="image" src="https://github.com/user-attachments/assets/c5af2dfb-63cf-4575-8dbc-73844988c61b" />


I reviewed the Rule setup and created the rule.

<img width="720" height="297" alt="image" src="https://github.com/user-attachments/assets/e2c46e5a-20c8-4ae9-a779-087891e13b35" />


<img width="720" height="28" alt="image" src="https://github.com/user-attachments/assets/c51c6184-ca02-405e-89d5-986fc83c4866" />


Rule has been created
Creating the rule alone is not enough to capture changes being made to services. I needed to go into the settings of the AWS Config recorder to make sure the AWS IAM Role and AWS IAM Policy resources were added to the list of resource types to record and set the frequency to continuous. Without this setup in place, changes made to IAM role and IAM policy will not trigger the lambda function because Config is not setup to record those.

<img width="720" height="393" alt="image" src="https://github.com/user-attachments/assets/4611c3d2-a484-46f5-a69a-67ca061c4eed" />


For this project, I only need IAM Policy and Role, but I had previously setup EC2, S3 and User for a different purpose, it is not needed here.

In order for Config to work, an s3 bucket needs to be setup as part of the delivery channel settings. Without the s3 bucket, Config will not work. The s3 bucket will be the storage location of the records of all changes made to the resources we selected to record under the Recorder. See the screenshot below.

<img width="720" height="443" alt="image" src="https://github.com/user-attachments/assets/aefa0262-734a-4788-83f9-cc9dfcdc10e8" />


I decided not to stream configuration changes because this will send the same information being recorded to s3 to the SNS topic which is not needed.

4. **IAM Permissions**: AWS will automatically create an IAM role for you and Config and will add a trust policy between config and the lambda function. However, the lambda function still needs additional permissions to access the IAM services I need to review. This is the default permission that AWS creates for the lambda function.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:us-east-1:accountID:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:us-east-1:accountID:log-group:/aws/lambda/IAMRoleAudit1:*"
            ]
        }
    ]
}
```
We need to add additional permissions to allow lambda to get role and policy information. This is what the policy document looks like after it’s modified.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:us-east-1:accountID:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:us-east-1:accountID:log-group:/aws/lambda/IAMRoleAudit1:*"
            ]
        },
        {
            "Sid": "IamReadForAudit",
            "Effect": "Allow",
            "Action": [
                "iam:ListRoles",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:GetRolePolicy",
                "iam:GetPolicy",
                "iam:GetPolicyVersion"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SnsPublishAlerts",
            "Effect": "Allow",
            "Action": "sns:Publish",
            "Resource": "arn:aws:sns:us-east-1:accountID:IAMRoleAudit2025"
        }
    ]
}
```
# Testing & Results
To test out the workflow of the system, I created an IAM Policy with excess permissions. Based on the Config rules I have in place and the lambda function, I expect to receive an email alert to the email I subscribed to the SNS Topic with.

I created the IAM policy using the JSON code below and named it OverPerm-1:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```
<img width="720" height="311" alt="image" src="https://github.com/user-attachments/assets/b7db27ec-e277-45fc-b624-ad8f8d702008" />

Over Permissive Policy
I reviewed the cloudwatch logs for the lambda function to confirm run successfully.

<img width="720" height="169" alt="image" src="https://github.com/user-attachments/assets/4b07da84-8e9f-4aad-bd4a-e3d09cef75c7" />


Within 2 minutes of creating the new IAM policy, I received the email alert below informing me of the findings after analyzing the policy statement.

>The email alert contained:

>Subject: IAM Alert: Misconfigured Policy ‘OverPerm-1’

>Findings:

>Wildcard action found in policy ‘OverPerm-1’

>Wildcard resource found in policy ‘OverPerm-1’

>Status: (not currently attached to any roles)

>Action Required: Review this role and apply the principle of least privilege by replacing wildcard permissions with specific actions and resources.

<img width="720" height="194" alt="image" src="https://github.com/user-attachments/assets/859076b1-66e6-47fb-b53c-6ab783308101" />


I decided to take this a step further and create a role and attach the misconfigured IAM policy to the role. I created a role called OverPerm-Role for an AWS account and attached the policy to it.

<img width="720" height="279" alt="image" src="https://github.com/user-attachments/assets/aa2c5652-9eb4-4bf6-a25c-6a0bd32398f3" />


Misconfigured Role
This time around, I received 2 email alerts. One for the IAM Policy and another for the IAM Role.

<img width="720" height="243" alt="image" src="https://github.com/user-attachments/assets/0c5d9687-5ebc-4a05-8634-cd3da5095bac" />


The IAM policy alert now shows that it has been attached to a role and lists the role name in the alert.

<img width="720" height="201" alt="image" src="https://github.com/user-attachments/assets/d7c6ac94-cea4-4452-a8b3-27cc8079974e" />


The IAM role alert also points out what is causing the misconfiguration in the role and alerts me to review it.

Based on the results of these tests, I can confirm the workflow of the system is working as expected.

# Challenges I Encountered:
Getting this code right took several iterations. Initially, I ran into issues with:

**JSON parsing errors**: I initially tried to access event[‘configurationItem’] directly, but this caused a KeyError. I discovered that AWS Config wraps the configuration data in an invokingEvent field that contains a JSON string. I needed to first parse the invokingEvent using json.loads(), then extract the configurationItem from the parsed result. Adding this two-step parsing process fixed the issue.

**IAM permission errors**: My Lambda execution role initially didn’t have iam:GetPolicyVersion permission, so the function kept failing when trying to read policy documents. I had to update the role policy to include all necessary IAM read permissions.

**Timeout issues**: With the default 3-second timeout, the function was failing on roles with multiple attached policies. Increasing it to 30 seconds solved this.

**Recorder Issues**: Since my config was already previously setup, I forgot to make changes to the recording resources. As a result, when I made changes to the IAM Policies and IAM Roles, Config was not detecting the changes to trigger the lambda function. I realized what was happening when I reviewed the s3 bucket from my Config delivery channel setup and saw that config was not recording anything. I added the resources and made another change and the function triggered successfully.

# Conclusion
This IAM Role Auditing System demonstrates how AWS serverless services can be combined to create effective, low-cost security automation. The system successfully detects overly permissive IAM configurations within 2 minutes and operates at approximately $2–5/month, which is well within budget for any organization.

## Key Achievements:

1. Real-time detection and alerting for IAM misconfigurations.
2. Comprehensive monitoring of both roles and customer-managed policies.
3. Cost-effective operation using AWS free tier for Lambda and SNS.
4. Production-ready code with proper error handling and logging.

## Technical Skills Demonstrated:

1. Event-driven architecture using AWS Config and Lambda.
2. IAM policy analysis and security best practices.
3. AWS service integration and troubleshooting.
4. Serverless application development.
