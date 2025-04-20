from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User
from .models import Policy, CustomerPolicy
from .models import Claim



class UserRegistrationForm(UserCreationForm):
    role = forms.ChoiceField(choices=User.ROLE_CHOICES, required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'role']

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

class PolicyForm(forms.ModelForm):
    class Meta:
        model = Policy
        fields = ['name', 'policy_type', 'premium', 'coverage_amount', 'duration']

class ClaimForm(forms.ModelForm):
    class Meta:
        model = Claim
        fields = ['policy', 'description']

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user and user.role == 'customer':
            # Filter policies directly from the Policy model
            self.fields['policy'].queryset = Policy.objects.filter(
                id__in=user.purchased_policies.values_list('policy_id', flat=True)
            )