# views.py

from itertools import repeat
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from django.core.exceptions import ValidationError
from .forms import UserUpdateForm, ProfileUpdateForm
from django.contrib.auth.password_validation import validate_password
from django.shortcuts import render, redirect
from django.contrib.auth import update_session_auth_hash
from auth_app.models import PasswordReset  # Make sure to import your PasswordReset model
import uuid

# Custom 404 handler view
def custom_404_view(request, exception=None):
    return render(request, '404.html', status=404)

# Home/profile page for authenticated users
# Profile view to update user info and profile picture
@login_required
def Home(request):
    # Check if the user has a profile
    if not hasattr(request.user, 'profile'):
        messages.error(request, "Your profile does not exist. Please complete your registration.")
        return redirect('register')  # Redirect to the registration or profile creation page

    if request.method == 'POST':
        u_form = UserUpdateForm(request.POST, instance=request.user)
        p_form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user.profile)

        if u_form.is_valid() and p_form.is_valid():
            u_form.save()
            p_form.save()
            messages.success(request, 'Your profile has been updated successfully!')
            return redirect('home')  # Redirect to the home view after successful update
    else:
        u_form = UserUpdateForm(instance=request.user)
        p_form = ProfileUpdateForm(instance=request.user.profile)

    context = {
        'u_form': u_form,
        'p_form': p_form
    }

    return render(request, 'profile.html', context)  # Ensure this return statement is present

@login_required
def EditProfle(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        new_password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Update email
        request.user.email = email
        request.user.save()

        # Handle password change if new password is provided
        if new_password:
            if new_password == confirm_password:
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)  # Important to keep the user logged in
                messages.success(request, 'Your settings have been updated.')
            else:
                messages.error(request, 'Passwords do not match.')
        else:
            messages.success(request, 'Your email has been updated.')

        return redirect('settings')  # Redirect to settings page after updating

    return render(request, 'edit_profile.html')
# User registration view
def Register(request):
    if request.method == "POST":
        full_name = request.POST.get('full_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        repeat_password = request.POST.get('repeat_password')

        # Error flag for validation
        user_data_has_error = False

        # Check if username is already taken
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
            user_data_has_error = True

        # Check if email is already registered
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists")
            user_data_has_error = True

        # Validate password length and matching
        if password != repeat_password:
            messages.error(request, "Passwords do not match")
            user_data_has_error = True
        elif len(password) < 6:
            messages.error(request, "Password must be at least 6 characters")
            user_data_has_error = True

        if user_data_has_error:
            return redirect('register')

        # Create new user if no errors
        else:
            new_user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            new_user.first_name = full_name
            new_user.save()

            messages.success(request, "Account created successfully. You can now login.")
            return redirect('login')

    return render(request, 'register.html')

# User login view
def Login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)

            # Check if the user has a profile
            if not hasattr(user, 'profile'):
                messages.error(request, "Your profile does not exist. Please complete your registration.")
                return redirect('register')  # Redirect to profile creation or registration page

            return redirect('home')  # Redirect to home if login is successful
        else:
            messages.error(request, "Invalid login credentials")
            return redirect('login')

    return render(request, 'login.html')
# User logout view
@login_required
def Logout(request):
    logout(request)
    return redirect('login')

# Forgot password view
# Forgot password view
def Forgot(request):
    if request.method == "POST":
        email = request.POST.get('email')

        try:
            # Find the user by email
            user = User.objects.get(email=email)

            # Create a password reset request
            # Make sure you're passing the correct field expected by the PasswordReset model
            new_password_reset = PasswordReset(user=user)  # Adjust this based on your model
            new_password_reset.save()

            # Generate password reset URL
            password_reset_url = reverse('password-reset', kwargs={'reset_id': new_password_reset.reset_id})
            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'

            # Send password reset email
            email_body = f'Reset your password using the link below:\n\n{full_password_reset_url}'
            email_message = EmailMessage(
                'Reset your password',
                email_body,
                settings.EMAIL_HOST_USER,
                [email]
            )

            email_message.fail_silently = True
            email_message.send()

            messages.success(request, f"Password reset link has been sent to {email}.")
            return redirect('login')

        except User.DoesNotExist:
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forgot-password')

    return render(request, 'forgot_password.html')



# Password reset view (handle reset link)
def PasswordReset(request, reset_id):
    # Check if the reset request is valid or expired
    password_reset = get_object_or_404(PasswordReset, reset_id=reset_id)

    return render(request, 'password_reset.html', {'reset_id': reset_id})

# Change password view (after clicking reset link)
def ChangePassword(request, reset_id):
    try:
        # Validate password reset request
        password_reset = get_object_or_404(PasswordReset, reset_id=reset_id)

        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            passwords_have_error = False

            # Check if passwords match
            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, 'Passwords do not match')

            # Check password length and strength
            if len(password) < 6:
                passwords_have_error = True
                messages.error(request, 'Password must be at least 6 characters long')

            try:
                # Validate password using Django's password validators
                validate_password(password)
            except ValidationError as e:
                passwords_have_error = True
                messages.error(request, e.messages)

            # Check if the reset link has expired (valid for 10 minutes)
            expiration_time = password_reset.created_when + timezone.timedelta(minutes=10)
            if timezone.now() > expiration_time:
                passwords_have_error = True
                messages.error(request, 'Reset link has expired')
                password_reset.delete()

            if not passwords_have_error:
                # Update user's password
                user = password_reset.user
                user.set_password(password)
                user.save()

                # Delete the reset request after successful password change
                password_reset.delete()

                messages.success(request, 'Password reset successfully. You can now login.')
                return redirect('login')

        return render(request, 'password_reset.html', {'reset_id': reset_id})

    except PasswordReset.DoesNotExist:
        messages.error(request, 'Invalid or expired reset link')
        return redirect('forgot-password')
