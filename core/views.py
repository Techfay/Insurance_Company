from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from .forms import UserRegistrationForm, LoginForm
from .models import Policy, CustomerPolicy
from .forms import PolicyForm 
from django.contrib import messages
from botocore.exceptions import ClientError  # Import ClientError
from .models import Claim
from .forms import ClaimForm

from django.utils.timezone import now

from django.db.models import Count, Sum

import json

from django.http import HttpResponse

from django.contrib.auth import login

import boto3 # for aws services







import boto3
from django.conf import settings

def get_dynamodb_client():
    return boto3.resource(
        'dynamodb',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        aws_session_token=settings.AWS_SESSION_TOKEN,
        region_name=settings.AWS_REGION_NAME,
    )

def get_table(table_name):
    dynamodb = get_dynamodb_client()
    return dynamodb.Table(table_name)



def send_purchase_notification(customer, policy):
    """
    Sends an email notification using AWS SNS when a policy is purchased.
    """
    sns_client = boto3.client(
        'sns',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        aws_session_token=settings.AWS_SESSION_TOKEN,  # Optional if session token is required
        region_name=settings.AWS_REGION_NAME,
    )

    # Fetch customer email
    customer_email = customer.email

    # Subscribe the customer to the topic if not already subscribed
    topic_arn = settings.SNS_TOPIC_ARN
    subscription_arn = None

    try:
        response = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
        for subscription in response['Subscriptions']:
            if subscription['Endpoint'] == customer_email:
                subscription_arn = subscription['SubscriptionArn']
                break

        if not subscription_arn:
            # Dynamically subscribe the customer if not already subscribed
            response = sns_client.subscribe(
                TopicArn=topic_arn,
                Protocol='email',
                Endpoint=customer_email,
            )
            subscription_arn = response['SubscriptionArn']

    except Exception as e:
        print(f"Failed to subscribe {customer_email}: {e}")
        raise Exception(f"Failed to subscribe {customer_email}: {e}")

    # Ensure the subscription is confirmed
    if subscription_arn == 'PendingConfirmation':
        print(f"Subscription pending confirmation for {customer_email}.")
        return

    # Prepare and send the notification
    email_subject = "Policy Purchase Confirmation"
    email_message = f"""
    Dear {customer.first_name},

    Thank you for purchasing the policy '{policy.name}'.

    Policy Details:
    - Policy Name: {policy.name}
    - Coverage Amount: ${policy.coverage_amount}
    - Premium: ${policy.premium} per year

    You can now manage your policy in the Insurance Application.

    Best regards,
    Insurance Team
    """
                

                    
    try:
        response = sns_client.publish(
            TopicArn=settings.SNS_TOPIC_ARN,
            Message=email_message,
            Subject=email_subject,
        )
        print(f"Notification sent to {customer_email}: {response}")
    except Exception as e:
        print(f"Failed to send notification to {customer_email}: {e}")
        raise


@login_required
def my_policies(request):
    if request.user.role != 'customer':
        return redirect('dashboard')

    purchased_policies = CustomerPolicy.objects.filter(customer=request.user)

    return render(request, 'my_policies.html', {
        'purchased_policies': purchased_policies,
    })

# @login_required
# def available_policies(request):
#     if request.user.role != 'customer':
#         return redirect('dashboard')

#     table = get_table(settings.DYNAMODB_TABLE_POLICIES)

#     # Fetch all policies
#     response = table.scan()
#     policies = response.get('Items', [])

#     # Fetch customer's purchased policies
#     customer_table = get_table(settings.DYNAMODB_TABLE_CUSTOMER_POLICIES)
#     customer_policies = customer_table.scan(
#         FilterExpression=boto3.dynamodb.conditions.Attr('customer_id').eq(request.user.id)
#     ).get('Items', [])

#     purchased_policy_ids = {cp['policy_id'] for cp in customer_policies}

#     # Exclude purchased policies
#     available_policies = [policy for policy in policies if policy['id'] not in purchased_policy_ids]

#     return render(request, 'available_policies.html', {'available_policies': available_policies})

@login_required
def available_policies(request):
    if request.user.role != 'customer':
        return redirect('dashboard')

    # Exclude policies already purchased by the customer
    available_policies = Policy.objects.exclude(id__in=request.user.purchased_policies.values_list('policy_id', flat=True))

    return render(request, 'available_policies.html', {
        'available_policies': available_policies,
    })


# @login_required
# def policy_purchase(request, policy_id):
#     if request.user.role != 'customer':
#         return redirect('dashboard')

#     policy_table = get_table(settings.DYNAMODB_TABLE_POLICIES)
#     customer_policy_table = get_table(settings.DYNAMODB_TABLE_CUSTOMER_POLICIES)

#     # Fetch the policy
#     response = policy_table.get_item(Key={'id': policy_id})
#     policy = response.get('Item')
#     if not policy:
#         messages.error(request, "Policy not found.")
#         return redirect('available_policies')

#     # Add the policy to customer's purchased list
#     customer_policy_table.put_item(
#         Item={
#             'id': f'{request.user.id}_{policy_id}',
#             'customer_id': request.user.id,
#             'policy_id': policy_id,
#             'status': 'Pending',
#         }
#     )

#     # Redirect to payment page
#     return render(request, 'payment_gateway.html', {'policy': policy})
@login_required
def policy_purchase(request, policy_id):
    if request.user.role != 'customer':
        return redirect('dashboard')

    policy = get_object_or_404(Policy, id=policy_id)
    
    


    # Simulate payment gateway
    return render(request, 'payment_gateway.html', {'policy': policy})



# @login_required
# def payment_success(request, policy_id):
#     if request.user.role != 'customer':
#         return redirect('dashboard')

#     customer_policy_table = get_table(settings.DYNAMODB_TABLE_CUSTOMER_POLICIES)

#     # Update policy status to 'Purchased'
#     customer_policy_table.update_item(
#         Key={'id': f'{request.user.id}_{policy_id}'},
#         UpdateExpression='SET #status = :status',
#         ExpressionAttributeNames={'#status': 'status'},
#         ExpressionAttributeValues={':status': 'Purchased'},
#     )

#     # Fetch policy details for display
#     policy_table = get_table(settings.DYNAMODB_TABLE_POLICIES)
#     policy = policy_table.get_item(Key={'id': policy_id}).get('Item')

#     # Send purchase notification
#     send_purchase_notification(request.user, policy)

#     return render(request, 'payment_success.html', {'policy': policy})

@login_required
def payment_success(request, policy_id):
    if request.user.role != 'customer':
        return redirect('dashboard')

    policy = get_object_or_404(Policy, id=policy_id)

    # Create a record for purchased policy
    CustomerPolicy.objects.create(customer=request.user, policy=policy)
    policy = get_object_or_404(Policy, id=policy_id)

    send_purchase_notification(request.user, policy)

    # Prepare data for Lambda
    lambda_client = boto3.client(
        'lambda',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        aws_session_token=settings.AWS_SESSION_TOKEN,  # Optional
        region_name=settings.AWS_REGION_NAME,
    )

    payload = {
        "policy_id": str(policy.id),
        "customer_name": request.user.first_name,
        "customer_email": request.user.email,
        "policy_name": policy.name,
        "policy_details": policy.details,  # Assuming there's a 'details' field
    }
    try:
        response = lambda_client.invoke(
            FunctionName='GeneratePolicyPDF',
            InvocationType='RequestResponse',  # Synchronous invocation
            Payload=json.dumps(payload),
        )
        print(f"Lambda response: {response}")
        messages.success(request, f"Payment successful! Policy '{policy.name}' purchased.")
    except Exception as e:
        messages.error(request, f"Policy purchased, but failed to generate document: {e}")

    return render(request, 'payment_success.html', {'policy': policy})






def home(request):
    return render(request, 'home.html', {'title': 'Insurance Application'})

@login_required
def dashboard(request):
    role = request.user.role

    if role == "admin":
        return render(request, 'dashboard.html', {'role': role})
    elif role == "agent":
        policies_sold = CustomerPolicy.objects.filter(policy__created_by=request.user).count()
        target = 50  # Example sales target
        return render(request, 'agent_dashboard.html', {
            'role': role,
            'policies_sold': policies_sold,
            'target': target
        })
    elif role == "customer":
        return render(request, 'dashboard.html', {'role': role})

    return render(request, 'dashboard.html', {'role': role})


def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            # Save user in Django's database
            user = form.save()

            # Save user data to DynamoDB
            dynamodb = boto3.resource(
                'dynamodb',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                aws_session_token=settings.AWS_SESSION_TOKEN,  # Optional
                region_name=settings.AWS_REGION_NAME,
            )
            table = dynamodb.Table('Users')  # Replace 'Users' with your table name
            try:
                table.put_item(
                    Item={
                        'email': user.email,
                        'username': user.username,
                        'role': user.role,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'is_active': user.is_active,
                        'date_joined': str(user.date_joined),
                    }
                )
                messages.success(request, "User registered successfully and added to DynamoDB!")
            except ClientError as e:
                messages.error(request, f"Failed to add user to DynamoDB: {e.response['Error']['Message']}")

            # Log the user in
            login(request, user)
            return redirect('dashboard')
    else:
        form = UserRegistrationForm()
    return render(request, 'register.html', {'form': form})
# # from core.models import CustomerPolicy
# def register(request):
#     if request.method == 'POST':
#         form = UserRegistrationForm(request.POST)
#         if form.is_valid():
#             user = form.save()
#             # Update pending policies to 'Purchased' after registration
#             CustomerPolicy.objects.filter(customer=user, status='pending').update(status='Purchased')
#             login(request, user)
#             messages.success(request, 'Registration successful! Your policies are now active.')
#             return redirect('dashboard')  # Redirect to the customer dashboard
#     else:
#         form = UserRegistrationForm()
#     return render(request, 'register.html', {'form': form})


def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')  # Redirect to the dashboard
            else:
                form.add_error(None, 'Invalid credentials')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})


@login_required
def user_logout(request):
    logout(request)
    return redirect('login')


########## policy management #################


@login_required
def policy_list(request):
    policies = Policy.objects.filter(created_by=request.user)
    return render(request, 'policy_list.html', {'policies': policies})

@login_required

@login_required
def policy_create(request):
    if request.user.role != 'admin':
        return redirect('dashboard')

    if request.method == 'POST':
        form = PolicyForm(request.POST)
        if form.is_valid():
            policy = form.save(commit=False)
            policy.created_by = request.user
            policy.save()

            # Insert into DynamoDB
            dynamodb = boto3.resource(
                'dynamodb',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                aws_session_token=settings.AWS_SESSION_TOKEN,  # Optional if required
                region_name=settings.AWS_REGION_NAME,
            )
            table = dynamodb.Table('Policies')

            try:
                table.put_item(
                    Item={
                        'policy_id': str(policy.id),  # Use string type for compatibility
                        'name': policy.name,
                        'policy_type': policy.policy_type,
                        'coverage_amount': policy.coverage_amount,
                        'premium': policy.premium,
                        'created_by': policy.created_by.email,
                        'created_at': str(policy.created_at),  # Convert datetime to string
                    }
                )
                messages.success(request, "Policy created successfully and stored in DynamoDB!")
            except ClientError as e:
                messages.error(request, f"Failed to save policy in DynamoDB: {e.response['Error']['Message']}")
            except Exception as e:
                messages.error(request, f"Unexpected error: {str(e)}")

            return redirect('policy_list')
    else:
        form = PolicyForm()
    return render(request, 'policy_form.html', {'form': form})
# def policy_create(request):
#     if request.method == 'POST':
#         form = PolicyForm(request.POST)
#         if form.is_valid():
#             policy = form.save(commit=False)
#             policy.created_by = request.user
#             policy.save()
#             return redirect('policy_list')
#     else:
#         form = PolicyForm()
#     return render(request, 'policy_form.html', {'form': form})

@login_required
def policy_update(request, pk):
    policy = get_object_or_404(Policy, pk=pk, created_by=request.user)
    if request.method == 'POST':
        form = PolicyForm(request.POST, instance=policy)
        if form.is_valid():
            form.save()
            return redirect('policy_list')
    else:
        form = PolicyForm(instance=policy)
    return render(request, 'policy_form.html', {'form': form})

@login_required
def policy_delete(request, pk):
    if request.user.role != 'admin':
        return redirect('dashboard')

    policy = get_object_or_404(Policy, pk=pk, created_by=request.user)

    if request.method == 'POST':
        # Initialize the DynamoDB resource
        dynamodb = boto3.resource(
            'dynamodb',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.AWS_SESSION_TOKEN,  # Optional if session token is required
            region_name=settings.AWS_REGION_NAME,
        )
        table = dynamodb.Table('Policies')

        # Delete the policy from DynamoDB
        try:
            table.delete_item(
                Key={
                    'policy_id': str(policy.id),  # Ensure the key matches DynamoDB's primary key
                }
            )
            messages.success(request, "Policy deleted from the application and DynamoDB successfully!")
        except ClientError as e:
            messages.error(request, f"Failed to delete policy from DynamoDB: {e.response['Error']['Message']}")
        except Exception as e:
            messages.error(request, f"Unexpected error while deleting from DynamoDB: {str(e)}")

        # Delete the policy from the Django database
        policy.delete()
        return redirect('policy_list')

    return render(request, 'policy_confirm_delete.html', {'policy': policy})
# @login_required
# def policy_delete(request, pk):
#     policy = get_object_or_404(Policy, pk=pk, created_by=request.user)
#     if request.method == 'POST':
#         policy.delete()
#         return redirect('policy_list')
#     return render(request, 'policy_confirm_delete.html', {'policy': policy})


############### Claim management ##################



@login_required
def claim_list(request):
    claims = Claim.objects.filter(customer=request.user)
    return render(request, 'claim_list.html', {'claims': claims})




# @login_required
# def claim_create(request):
#     if request.user.role != 'customer':
#         return redirect('dashboard')

#     if request.method == 'POST':
#         description = request.POST.get('description')
#         policy_id = request.POST.get('policy_id')

#         claims_table = get_table(settings.DYNAMODB_TABLE_CLAIMS)

#         # Add claim to DynamoDB
#         claims_table.put_item(
#             Item={
#                 'id': f'{request.user.id}_{policy_id}',
#                 'customer_id': request.user.id,
#                 'policy_id': policy_id,
#                 'description': description,
#                 'status': 'Pending',
#                 'created_at': str(now()),
#             }
#         )

#         messages.success(request, "Your claim has been submitted successfully!")
#         return redirect('claim_list')

#     # Fetch purchased policies
#     customer_policy_table = get_table(settings.DYNAMODB_TABLE_CUSTOMER_POLICIES)
#     purchased_policies = customer_policy_table.scan(
#         FilterExpression=boto3.dynamodb.conditions.Attr('customer_id').eq(request.user.id)
#     ).get('Items', [])

#     return render(request, 'claim_form.html', {'purchased_policies': purchased_policies})
@login_required
def claim_create(request):
    if request.user.role != 'customer':
        return redirect('dashboard')

    if request.method == 'POST':
        form = ClaimForm(request.POST, user=request.user)
        if form.is_valid():
            claim = form.save(commit=False)
            claim.customer = request.user
            claim.status = 'Pending'
            claim.save()

            # Save claim to DynamoDB
            dynamodb = boto3.resource(
                'dynamodb',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                aws_session_token=settings.AWS_SESSION_TOKEN,  # Optional
                region_name=settings.AWS_REGION_NAME
            )
            claims_table = dynamodb.Table(settings.DYNAMODB_TABLE_CLAIMS)

            try:
                # Insert claim into DynamoDB
                claims_table.put_item(
                    Item={
                        'ClaimID': str(claim.id),  # Use the claim ID as a unique identifier
                        'CustomerID': str(request.user.id),
                        'PolicyID': str(claim.policy.id),
                        'Description': claim.description,
                        'Status': claim.status,
                        'CreatedAt': claim.created_at.isoformat(),
                        'ReviewedAt': claim.reviewed_at.isoformat() if claim.reviewed_at else None,
                        'ReviewedBy': str(claim.reviewed_by.id) if claim.reviewed_by else None,
                    }
                )
                print(f"Claim {claim.id} saved to DynamoDB.")
            except ClientError as e:
                print(f"Failed to save claim {claim.id} to DynamoDB: {e.response['Error']['Message']}")

            messages.success(request, "Your claim has been submitted successfully!")
            return redirect('claim_list')
    else:
        form = ClaimForm(user=request.user)

    return render(request, 'claim_form.html', {'form': form})
# @login_required
# def claim_create(request):
#     if request.user.role != 'customer':
#         return redirect('dashboard')

#     if request.method == 'POST':
#         form = ClaimForm(request.POST, user=request.user)
#         if form.is_valid():
#             claim = form.save(commit=False)
#             claim.customer = request.user
#             claim.status = 'Pending'
#             claim.save()
#             messages.success(request, "Your claim has been submitted successfully!")
#             return redirect('claim_list')
#     else:
#         form = ClaimForm(user=request.user)

#     return render(request, 'claim_form.html', {'form': form})


@login_required
def claim_review(request):
    if request.user.role not in ['admin', 'agent']:
        return redirect('dashboard')

    claims = Claim.objects.filter(status='Pending')
    return render(request, 'claim_review.html', {'claims': claims})




    

@login_required
def claim_process(request, pk, action):
    if request.user.role not in ['admin', 'agent']:
        return redirect('dashboard')

    claim = get_object_or_404(Claim, pk=pk)
    if action.lower() == 'approve':
        claim.status = 'Approved'
    elif action.lower() == 'reject':
        claim.status = 'Rejected'
    else:
        messages.error(request, "Invalid action. Please select either 'approve' or 'reject'.")
        return redirect('claim_review')

    claim.reviewed_at = now()
    claim.reviewed_by = request.user
    claim.save()

    customer_email = claim.customer.email
    
    print(customer_email)

    """
    Sends an email notification using AWS SNS regarding claim status.
    """
    sns_client = boto3.client(
        'sns',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        aws_session_token=settings.AWS_SESSION_TOKEN,  # Optional: Use if session token is required
        region_name=settings.AWS_REGION_NAME,
    )

    # Fetch all subscriptions to the SNS topic
    topic_arn = settings.SNS_TOPIC_ARN
    email_address = claim.customer.email  # Corrected to use 'customer'
    subscription_arn = None

    
    # Fetch the SubscriptionArn for the specific email
    try:
        response = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
        for subscription in response['Subscriptions']:
            if subscription['Endpoint'] == email_address:
                subscription_arn = subscription['SubscriptionArn']
                break
    except Exception as e:
        raise Exception(f"Failed to retrieve subscription for {email_address}: {e}")
    if not subscription_arn or subscription_arn == 'PendingConfirmation':
        raise Exception(f"The email {email_address} is not subscribed or confirmation is pending.")
    # Prepare the notification message
    email_subject = f"Your Claim has been {claim.status}"
    email_message = f"""
    Dear {claim.customer.first_name},

    Your claim for the policy '{claim.policy.name}' has been {claim.status} by .

    Status: {claim.status}
    Reviewed on: {claim.reviewed_at.strftime('%Y-%m-%d %H:%M:%S')}
    Policy: {claim.policy.name}

    If you have any questions, please contact us.

    Best regards,
    Insurance Team
    """
    print(subscription_arn)
    topic_arn = settings.SNS_TOPIC_ARN
    # Publish the notification to the specific email subscription
    sns_client.publish(
        TopicArn=settings.SNS_TOPIC_ARN,
        Message=email_message,
        Subject=email_subject,

    )

    return redirect('claim_review')



@login_required
def reports(request):
    if request.user.role != 'admin' and request.user.role != 'agent':
        return redirect('dashboard')

    # Key Metrics
    total_policies = Policy.objects.count()
    total_claims = Claim.objects.count()
    pending_claims = Claim.objects.filter(status='pending').count()
    approved_claims = Claim.objects.filter(status='approved').count()
    total_revenue = Policy.objects.aggregate(revenue=Sum('premium'))['revenue'] or 0

    # Data for Charts
    policies_by_type = list(
        Policy.objects.values('policy_type')
        .annotate(count=Count('id'))
        .order_by('policy_type')
    )
    claims_by_status = list(
        Claim.objects.values('status')
        .annotate(count=Count('id'))
        .order_by('status')
    )
    # print("Policies by Type:", policies_by_type)  # Debugging
    # print("Claims by Status:", claims_by_status)  # Debugging
        # Serialize to JSON for safe usage in templates
    policies_by_type_json = json.dumps(policies_by_type)
    claims_by_status_json = json.dumps(claims_by_status)

    context = {
        'policies_by_type_json': policies_by_type_json,
        'claims_by_status_json': claims_by_status_json,
        'total_policies': Policy.objects.count(),
        'total_claims': Claim.objects.count(),
        'pending_claims': Claim.objects.filter(status='pending').count(),
        'approved_claims': Claim.objects.filter(status='approved').count(),
        'total_revenue': Policy.objects.aggregate(Sum('premium'))['premium__sum'] or 0,
    }


    return render(request, 'reports.html', context)


######### Agent ##########

@login_required
def agent_dashboard(request):
    if request.user.role != 'agent':
        return redirect('dashboard')

    # Get policies created by admin
    policies = Policy.objects.all()

    # Count policies sold by the agent
    policies_sold = CustomerPolicy.objects.filter(policy__in=policies, customer=request.user).count()

    # Define a target for the agent (example: 50 policies)
    target = 50

    return render(request, 'agent_dashboard.html', {
        'policies': policies,
        'policies_sold': policies_sold,
        'target': target,
    })


@login_required
def agent_available_policies(request):
    if request.user.role != 'agent':
        return redirect('dashboard')

    policies = Policy.objects.all()  # Display all policies created by admin
    return render(request, 'agent_available_policies.html', {'policies': policies})

@login_required
def agent_sales_performance(request):
    if request.user.role != 'agent':
        return redirect('dashboard')

    # Fetch policies sold by the agent (assuming they handle the sale)
    sold_policies = CustomerPolicy.objects.select_related('policy', 'customer').all()
    for policy in sold_policies:
        print(f"Policy: {policy.policy.name}, Status: {policy.status}, Customer: {policy.customer.username}")

    # Count total policies sold
    policies_sold = sold_policies.count()

    # Define a sales target (e.g., 50 policies)
    target = 50

    return render(request, 'agent_sales_performance.html', {
        'sold_policies': sold_policies,
        'policies_sold': policies_sold,
        'target': target,
    })


from django.utils.crypto import get_random_string  
from django.contrib.auth import get_user_model  # Import for custom user model
from django.contrib import messages  # Import for messages
from django.core.mail import send_mail
from django.conf import settings

User = get_user_model()  # Dynamically fetch the custom user model

from django.db import IntegrityError
@login_required
def sell_policy(request, policy_id):
    if request.user.role != 'agent':
        return redirect('dashboard')

    policy = get_object_or_404(Policy, id=policy_id)

    if request.method == "POST":
        customer_name = request.POST.get("customer_name")
        customer_email = request.POST.get("customer_email")

        # Check if a user with the email exists
        customer = User.objects.filter(email=customer_email).first()

        if customer:
            # If the user already exists, resend the email
            signup_link = f"{request.build_absolute_uri('/register/')}?email={customer_email}"
            email_subject = "Policy Purchase Confirmation (Resend)"
            email_message = f"""
            Dear { customer_name or customer.first_name },

            You have already been assigned the policy '{policy.name}'.

            To activate your account and manage your policy, please sign up using the link below:
            {signup_link}

            Best regards,
            Insurance Team
            """
        else:
            # Generate a unique username
            base_username = customer_email.split('@')[0]
            username = base_username
            while User.objects.filter(username=username).exists():
                username = f"{base_username}_{get_random_string(4)}"

            # Create a new user
            customer = User.objects.create(
                email=customer_email,
                username=username,
                first_name=customer_name,
                role='customer',
                is_active=False,
            )

            # Create the email message
            signup_link = f"{request.build_absolute_uri('/register/')}?email={customer_email}"
            email_subject = "Policy Purchase Confirmation"
            email_message = f"""
            Dear {customer_name},

            Congratulations! You've been assigned the policy '{policy.name}'.

            To activate your account and manage your policy, please sign up using the link below:
            {signup_link}

            Best regards,
            Insurance Team
            """

        # Create or update the policy entry for the customer
        CustomerPolicy.objects.update_or_create(
            customer=customer, policy=policy, defaults={'status': 'Pending'}
        )

        # Initialize the SNS client
        sns_client = boto3.client(
            'sns',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.AWS_SESSION_TOKEN,  # Include the session token
            region_name=settings.AWS_REGION_NAME,
        )
        topic_arn = settings.SNS_TOPIC_ARN

        # Dynamic subscription
        try:
            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
            flag=0
            for subscription in subscriptions.get('Subscriptions', []):
                
                if (subscription['Endpoint'] == customer_email) :
                        sns_client.publish(
                            TopicArn=topic_arn,
                            Message=email_message,
                            Subject=email_subject
                        )
                        messages.success(request, f"Policy '{policy.name}' successfully assigned to {customer_name}. Notification sent!")
                        flag = 1
                        break

            if(flag == 0):
                messages.warning(
                    request, f"Policy assigned, but the email subscription is pending confirmation for {customer_email}."
                )
                subscription_response = sns_client.subscribe(
                TopicArn=topic_arn,
                Protocol='email',
                Endpoint=customer_email
                )   


                    

        except Exception as e:
            messages.error(request, f"Failed to subscribe customer to notifications: {e}")

        # Send the notification

        return redirect('agent_sales_performance')

    return render(request, 'sell_policy.html', {'policy': policy})

from django.http import JsonResponse


@login_required
def confirm_payment(request, policy_id):

    customer_policy = get_object_or_404(CustomerPolicy, customer=request.user, policy_id=policy_id, status='Pending')

    if request.method == "POST":
        # Simulate payment confirmation
        customer_policy.status = 'Purchased'
        customer_policy.save()
        return JsonResponse({'message': 'Payment successful! Policy has been activated.'})
    


    # premisum calculation 

from django.shortcuts import render
from django.http import HttpResponse
from premium_calculator.premium_calculator import calculate_life_premium, calculate_health_premium, calculate_vehicle_premium

# Life Insurance Calculator View
def life_premium_calculator(request):
    result = None
    if request.method == 'POST':
        age = int(request.POST.get('age'))
        coverage = float(request.POST.get('coverage'))
        term = int(request.POST.get('term'))
        result = calculate_life_premium(age, coverage, term)
    return render(request, 'life_premium_calculator.html', {'result': result})





# Health Insurance Calculator View
def health_premium_calculator(request):
    result = None
    if request.method == 'POST':
        age = int(request.POST.get('age'))
        coverage = float(request.POST.get('coverage'))
        pre_existing_conditions = request.POST.get('pre_existing_conditions') == 'yes'
        result = calculate_health_premium(age, coverage, pre_existing_conditions)
    return render(request, 'health_premium_calculator.html', {'result': result})

# Vehicle Insurance Calculator View
def vehicle_premium_calculator(request):
    result = None
    if request.method == 'POST':
        vehicle_age = int(request.POST.get('vehicle_age'))
        vehicle_value = float(request.POST.get('vehicle_value'))
        driver_age = int(request.POST.get('driver_age'))
        result = calculate_vehicle_premium(vehicle_age, vehicle_value, driver_age)
    return render(request, 'vehicle_premium_calculator.html', {'result': result})

def premium_calculator_overview(request):
    return render(request, 'premium_calculator_overview.html')



























# Hangzhou

# Zhengzhou



# export 
# export 
# export 
# export 


# eb setenv AWS_ACCESS_KEY_ID=ASIAQJN5JZQ3CPHNJFXC AWS_SECRET_ACCESS_KEY=xDcRMRJTHO3HW6IbRNAdPsu6OaccXupmjPbyH4u0 AWS_REGION=us-east-1 DB_TABLE_NAME="Bookings"  AWS_SESSION_TOKEN='IQoJb3JpZ2luX2VjEAYaCXVzLXdlc3QtMiJIMEYCIQD5IZO8Q3UdazIprmRWlyVcs9vAcNL6nitMetIQ9+95mwIhAMuSKF01MitpfrOJgg+OTyN81oj1Dn97EqXncDbgdJIeKr0CCK///////////wEQABoMMDIwMjYxMjI3NTc0Igy7UkGo/kjTt+nuq0kqkQICGOIXLksBcuyxbV8GG1Y547KUK7z9AlYGdCQHrtAK0w8ZFr2K3T0ZyAoTCHiS6CRoTL+w6GnB2FLU2HBrfN6RqgQmg+1JO8omvCLqrzw+5rFtOHe8DS5hZ0QPweZuYT747EgE2+tO13HLD9Pj8q/cnsqlPlIyGZ3eWV3aioKTojt18ndiwXz4+CUeJ5Z6F9Su0GTMcDXNpvcIs1jnw3ylLa63NhNVw75MbGJblLhsPFDkgWS9GtA6ODKd4IMtSi7muI9t4GTeaU61bcehSzvUb1ME1DDrg0uYMYbv89LZ80asho2bqBVzZcfKNy807Um7zgAzUF05JnpU7cdKxDaHDH6bDc9BhaCQtlx/8a0Q7SAwrbGzugY6nAGVu7qKkkFFCgsyKraYEMlvKd4tsi+UNEKXTvoYCfh686NtJNdrBpl+KQyveZh4VSAG+dXyRfA0qUQFebML3YsPx6bGwZgbqm07uu/UZldifZYk3jHS5af669Zm/PlJ57fyyaOZ2FnJO09DqrF+OSL5gBucHzuzhIHhtYFH4KXrivnkIqDSj0WctpAXa7qAjdqQl/la17zLaOcrm7k='




















