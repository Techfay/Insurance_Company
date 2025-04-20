from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from django.utils.timezone import now

# from .models import Policy
from django.conf import settings  # Use settings.AUTH_USER_MODEL instead of get_user_model

class CustomerPolicy(models.Model):
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Purchased', 'Purchased'),
    )

    customer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="purchased_policies")
    policy = models.ForeignKey('Policy', on_delete=models.CASCADE)
    purchased_at = models.DateTimeField(default=now)  # Automatically set purchase date
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')  # Track purchase status
    # status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    def __str__(self):
        return f"{self.customer.username} - {self.policy.name} ({self.status})"

    
class User(AbstractUser):
    ROLE_CHOICES = (
        ('customer', 'Customer'),
        ('agent', 'Agent'),
        ('admin', 'Admin'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='customer')

    def __str__(self):
        return f"{self.username} ({self.role})"
    
######### policy management ##########
    
class Policy(models.Model):
    POLICY_TYPES = (
        ('life', 'Life Insurance'),
        ('health', 'Health Insurance'),
        ('auto', 'Auto Insurance'),
        ('property', 'Property Insurance'),
    )

    name = models.CharField(max_length=100)
    policy_type = models.CharField(max_length=20, choices=POLICY_TYPES)
    premium = models.DecimalField(max_digits=10, decimal_places=2)
    coverage_amount = models.DecimalField(max_digits=15, decimal_places=2)
    duration = models.PositiveIntegerField(help_text="Duration in years")
    details = models.TextField(default="Default policy details")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="policies"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

######## Claim management #############

class Claim(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )

    policy = models.ForeignKey(Policy, on_delete=models.CASCADE, related_name='claims')
    # claimant = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="claims")
    description = models.TextField()
    customer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="customar"
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_claims'
    )

    def __str__(self):
        return f"Claim for {self.policy.name} by {self.customer.username}"