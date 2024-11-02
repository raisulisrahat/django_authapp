# forms.py

from django import forms
from django.contrib.auth.models import User
from .models import Profile

# Form for updating user information
class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email']

# Form for updating profile information including profile picture
class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['profile_picture', 'bio', 'location']
