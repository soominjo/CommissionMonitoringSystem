from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from .forms import *
from .models import TrancheRecord
from decimal import Decimal
from .models import *
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.db.models import Sum, Q
from django.db import models
from django.urls import reverse, reverse_lazy
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation, ROUND_HALF_UP
from datetime import datetime, timedelta
from django.db import IntegrityError
from django.utils import timezone
from django.db.models.functions import TruncMonth, Concat
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.core.paginator import Paginator
import json
from collections import OrderedDict
from django.template.defaulttags import register
import logging

# Set up logging
logger = logging.getLogger(__name__)
from django.contrib.auth.decorators import user_passes_test
from django.core.files.base import ContentFile
import base64


def find_agent_user_by_name(agent_name):
    """
    Helper function to find a User object by agent name with multiple fallback strategies.
    Returns the User object if found, None otherwise.
    """
    if not agent_name or not agent_name.strip():
        return None
    
    agent_name = agent_name.strip()
    
    # Strategy 1: Try exact full name match (case insensitive)
    agent_user = User.objects.annotate(
        full_name=Concat('first_name', models.Value(' '), 'last_name')
    ).filter(full_name__iexact=agent_name).first()
    
    if agent_user:
        return agent_user
    
    # Strategy 2: Try exact first and last name match (case insensitive)
    name_parts = agent_name.split()
    if len(name_parts) >= 2:
        agent_user = User.objects.filter(
            Q(first_name__iexact=name_parts[0]) &
            Q(last_name__iexact=name_parts[-1])
        ).first()
        
        if agent_user:
            return agent_user
    
    # Strategy 3: Try username match (case insensitive)
    agent_user = User.objects.filter(username__iexact=agent_name).first()
    if agent_user:
        return agent_user
    
    # Strategy 4: Try contains match for first and last name
    if len(name_parts) >= 2:
        agent_user = User.objects.filter(
            Q(first_name__icontains=name_parts[0]) &
            Q(last_name__icontains=name_parts[-1])
        ).first()
        
        if agent_user:
            return agent_user
    
    # Strategy 5: Try partial full name match
    users_with_similar_names = User.objects.annotate(
        full_name=Concat('first_name', models.Value(' '), 'last_name')
    ).filter(full_name__icontains=agent_name)
    
    if users_with_similar_names.exists():
        return users_with_similar_names.first()
    
    return None


def fix_orphaned_commissions():
    """
    Utility function to fix Commission records that might have incorrect agent assignments
    and create missing commission records for payments that have been received.
    """
    fixed_count = 0
    error_count = 0
    created_count = 0
    
    # Get all tranche records
    tranche_records = TrancheRecord.objects.all()
    
    for record in tranche_records:
        # Find the correct agent user
        agent_user = find_agent_user_by_name(record.agent_name)
        
        if agent_user:
            # Look for commissions with release numbers that match this tranche
            for payment in record.payments.all():
                if payment.received_amount > 0:
                    release_code = f"LTO-{record.id}-1" if payment.is_lto else f"DP-{record.id}-{payment.tranche_number}"
                    
                    # Check if commission record exists for the correct agent
                    existing_commission = Commission.objects.filter(
                        release_number=release_code,
                        agent=agent_user
                    ).first()
                    
                    # Also check for any commission with this release code (regardless of agent)
                    any_commission = Commission.objects.filter(
                        release_number=release_code
                    ).first()
                    
                    if existing_commission:
                        # Update existing commission if amount differs
                        if existing_commission.commission_amount != payment.received_amount:
                            existing_commission.commission_amount = payment.received_amount
                            existing_commission.date_released = payment.date_received
                            existing_commission.save()
                            fixed_count += 1
                            logger.info(f'Updated commission {release_code}: amount changed to ₱{payment.received_amount}')
                    elif any_commission:
                        # Commission exists but for wrong agent - reassign it
                        old_agent = any_commission.agent
                        any_commission.agent = agent_user
                        any_commission.commission_amount = payment.received_amount
                        any_commission.date_released = payment.date_received
                        any_commission.save()
                        fixed_count += 1
                        logger.info(f'Fixed commission {release_code}: reassigned from {old_agent.get_full_name()} to {agent_user.get_full_name()}')
                    else:
                        # Create missing commission record
                        new_commission = Commission.objects.create(
                            date_released=payment.date_received or timezone.now().date(),
                            release_number=release_code,
                            project_name=record.project_name,
                            developer=record.project_name.split()[0] if record.project_name else 'Unknown',
                            buyer=record.buyer_name,
                            agent=agent_user,
                            commission_amount=payment.received_amount
                        )
                        created_count += 1
                        logger.info(f'Created missing commission {release_code}: ₱{payment.received_amount} for {agent_user.get_full_name()}')
        else:
            error_count += 1
            logger.warning(f'Could not find agent user for: {record.agent_name}')
    
    return fixed_count + created_count, error_count


def perform_excel_tranche_calculations(total_contract_price, commission_rate, vat_rate=12, 
                                     withholding_tax_rate=10, process_fee_percentage=0,
                                     option1_percentage=50, option2_percentage=50, other_deductions=0):
    """
    Perform tranche calculations for Excel processing
    """
    # Convert percentages to decimals
    commission_rate_decimal = commission_rate / Decimal(100)
    vat_rate_decimal = vat_rate / Decimal(100)
    withholding_tax_rate_decimal = withholding_tax_rate / Decimal(100)
    process_fee_decimal = process_fee_percentage / Decimal(100)
    option1_decimal = option1_percentage / Decimal(100)
    option2_decimal = option2_percentage / Decimal(100)
    
    # Calculate base amounts
    net_of_vat = total_contract_price / (Decimal(1) + vat_rate_decimal)
    vat_amount = total_contract_price - net_of_vat
    gross_commission = net_of_vat * commission_rate_decimal
    
    # Calculate process fee
    process_fee = gross_commission * process_fee_decimal
    
    # Calculate net commission after process fee
    net_commission_after_fee = gross_commission - process_fee
    
    # Calculate withholding tax
    withholding_tax = net_commission_after_fee * withholding_tax_rate_decimal
    
    # Calculate net commission after all deductions
    net_commission = net_commission_after_fee - withholding_tax - other_deductions
    
    # Split into tranches
    dp_amount = net_commission * option1_decimal
    lto_amount = net_commission * option2_decimal
    
    return {
        'total_contract_price': float(total_contract_price),
        'net_of_vat': float(net_of_vat),
        'vat_amount': float(vat_amount),
        'gross_commission': float(gross_commission),
        'process_fee': float(process_fee),
        'withholding_tax': float(withholding_tax),
        'other_deductions': float(other_deductions),
        'net_commission': float(net_commission),
        'dp_amount': float(dp_amount),
        'lto_amount': float(lto_amount),
        'commission_rate': float(commission_rate),
        'vat_rate': float(vat_rate),
        'withholding_tax_rate': float(withholding_tax_rate),
        'process_fee_percentage': float(process_fee_percentage),
        'option1_percentage': float(option1_percentage),
        'option2_percentage': float(option2_percentage)
    }

# ---------------- Email confirmation helpers -----------------

def send_activation_email(request, user):
    """Send activation link to the user's email address."""
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    activation_link = request.build_absolute_uri(
        reverse('activate_account', kwargs={'uidb64': uid, 'token': token})
    )
    subject = 'Confirm your Inner SPARC account'
    message = f"""Hi {user.get_full_name() or user.username},

Thank you for registering with Inner SPARC!

To complete your registration and start using your account, please confirm your email address by clicking the link below:

{activation_link}

This link will verify your email and activate your account so you can:
• Access your personalized dashboard
• View and manage your sales monitoring data
• Create and view commission slips and tranches
• Stay updated with the latest announcements and features

If you did not sign up for Inner SPARC, please ignore this email. Your account will not be activated unless you click the confirmation link.

If you have any questions or need assistance, feel free to contact our support team at innersparc07@gmail.com.

Welcome aboard, and we look forward to working with you!

Best regards,
Inner SPARC Team"""

    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)


def send_approval_email(request, user):
    """Send account approval email to user."""
    sign_in_link = request.build_absolute_uri(reverse('signin'))
    subject = 'Your Inner SPARC Account Has Been Approved'
    message = f"""Hi {user.get_full_name() or user.username},

Great news! Your account has been successfully approved by Inner SPARC Realty Corporation.

You can now sign in and start accessing your account to:
• View and manage your sales records
• Generate and print commission slips
• Monitor tranches and incentive reports
• Stay updated with the latest company announcements and tools

To get started, please log in using the link below:

{sign_in_link}

If you have any questions or need assistance with your account, please contact our support team at innersparc07@gmail.com.

Welcome to Inner SPARC! We look forward to supporting your success.

Best regards,
Inner SPARC Team"""
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)


def activate_account(request, uidb64, token):
    """Activate user account after verifying email token."""
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError, OverflowError):
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations! Your email has been verified. You can now sign in once an administrator approves your account.')
    else:
        messages.error(request, 'Activation link is invalid or has expired.')
    return redirect('signin')





def home(request):
    # If the visitor is not logged in, send them to the sign-in page instead of showing the main app shell
    if not request.user.is_authenticated:
        return render(request, 'signin.html')
    else:
        # Redirect authenticated users to their profile/dashboard
        return redirect('profile')

def navbar(request):
    return render(request, 'navbar.html')

def signin(request):
    if request.user.is_authenticated:
        return redirect("profile")  # Redirect to profile if already logged in

    if request.method == "POST":
        username_or_email = request.POST.get("username_or_email")
        password = request.POST.get("password")

        print(f"DEBUG: Login attempt - Username/Email: {username_or_email}")

        if not username_or_email or not password:
            messages.error(request, 'Both username/email and password are required')
            return render(request, "signin.html")
        
        try:
            # Find user by email or username
            if '@' in username_or_email:
                user = User.objects.get(email=username_or_email)
                print(f"DEBUG: Found user by email: {user.username}")
            else:
                user = User.objects.get(username=username_or_email)
                print(f"DEBUG: Found user by username: {user.username}")
            
            print(f"DEBUG: User is_superuser: {user.is_superuser}, is_staff: {user.is_staff}, is_active: {user.is_active}")
            
            # Now authenticate with the found user's username
            auth_user = authenticate(request, username=user.username, password=password)
            
            print(f"DEBUG: Authentication result: {auth_user is not None}")
            
            if auth_user is None:
                messages.error(request, f'Invalid password for user: {user.username}')
                return render(request, "signin.html")
            
            if not auth_user.is_active:
                messages.error(request, 'Your account has been deactivated. Please contact administrator.')
                return render(request, "signin.html")
            
            # Skip approval check for superusers and staff
            if auth_user.is_superuser or auth_user.is_staff:
                print(f"DEBUG: Logging in superuser/staff: {auth_user.username}")
                login(request, auth_user)
                messages.success(request, f'Welcome back, {auth_user.get_full_name() or auth_user.username}!')
                return redirect("profile")
            
            # Check if user is approved (for regular users)
            try:
                if auth_user.profile.is_approved:
                    login(request, auth_user)
                    messages.success(request, f'Welcome back, {auth_user.get_full_name() or auth_user.username}!')
                    return redirect("profile")
                else:
                    messages.warning(request, 'Your account is pending approval. Please wait for administrator approval.')
                    return render(request, "signin.html")
            except AttributeError:
                messages.error(request, 'User profile not found. Please contact administrator.')
                return render(request, "signin.html")
                
        except User.DoesNotExist:
            messages.error(request, f'No account found with username/email: {username_or_email}')
            return render(request, "signin.html")
        except Exception as e:
            print(f"DEBUG: Unexpected error during signin: {str(e)}")
            messages.error(request, f'An error occurred during signin: {str(e)}')
            return render(request, "signin.html")

    return render(request, "signin.html")

@login_required
def signout(request):
    logout(request)
    return redirect("signin")

def signup(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            try:
                user = form.save(commit=False)
                user.is_active = False  # Require email confirmation
                # Set password directly using set_password
                user.set_password(form.cleaned_data['password1'])
                # Save first and last name to built-in User model fields
                user.first_name = form.cleaned_data.get('first_name', '')
                user.last_name = form.cleaned_data.get('last_name', '')
                user.save()
                # Send confirmation email
                send_activation_email(request, user)
                
                # Create profile
                Profile.objects.create(
                    user=user,
                    role=form.cleaned_data.get('role'),
                    team=form.cleaned_data.get('team'),
                    phone_number=form.cleaned_data.get('phone_number'),
                    first_name=form.cleaned_data.get('first_name'),
                    last_name=form.cleaned_data.get('last_name'),
                    is_approved=False  # Set initial approval status
                )
                
                messages.success(request, 'Account created successfully! Please confirm your email address. Check your inbox for the activation link.')
                return redirect('signin')
            except IntegrityError:
                messages.error(request, 'This username is already taken. Please choose a different username.')
                return render(request, 'signup.html', {'form': form})
    else:
        form = SignUpForm()

    return render(request, 'signup.html', {'form': form})


@login_required
@user_passes_test(lambda u: u.is_superuser)
def fix_commission_assignments(request):
    """
    Superuser-only view to diagnose and fix commission assignment issues.
    """
    if request.method == 'POST':
        try:
            fixed_count, error_count = fix_orphaned_commissions()
            if fixed_count > 0:
                messages.success(request, f'Successfully fixed {fixed_count} commission assignments.')
            if error_count > 0:
                messages.warning(request, f'{error_count} agent names could not be matched to user accounts.')
            if fixed_count == 0 and error_count == 0:
                messages.info(request, 'No commission assignment issues found.')
        except Exception as e:
            messages.error(request, f'Error fixing commission assignments: {str(e)}')
        
        return redirect('fix_commission_assignments')
    
    # GET request - show diagnostic information
    # Get all tranche records and check for potential issues
    tranche_records = TrancheRecord.objects.all()
    issues = []
    
    for record in tranche_records:
        agent_user = find_agent_user_by_name(record.agent_name)
        if not agent_user:
            issues.append({
                'tranche_id': record.id,
                'project_name': record.project_name,
                'agent_name': record.agent_name,
                'issue': 'Agent name does not match any user account'
            })
        else:
            # Check if commissions exist for this agent
            for payment in record.payments.all():
                if payment.received_amount > 0:
                    release_code = f"LTO-{record.id}-1" if payment.is_lto else f"DP-{record.id}-{payment.tranche_number}"
                    commission_exists = Commission.objects.filter(
                        release_number=release_code,
                        agent=agent_user
                    ).exists()
                    
                    if not commission_exists:
                        issues.append({
                            'tranche_id': record.id,
                            'project_name': record.project_name,
                            'agent_name': record.agent_name,
                            'release_code': release_code,
                            'issue': f'Commission record missing for payment of ₱{payment.received_amount}'
                        })
    
    # Get all active users for reference
    active_users = User.objects.filter(is_active=True).values('username', 'first_name', 'last_name')
    
    context = {
        'issues': issues,
        'active_users': active_users,
        'total_issues': len(issues)
    }
    
    return render(request, 'fix_commission_assignments.html', context)


@login_required
@user_passes_test(lambda u: u.is_superuser)
def create_user_by_superuser(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            try:
                user = form.save(commit=False)
                user.is_active = True  # Activate immediately
                user.set_password(form.cleaned_data['password1'])
                user.first_name = form.cleaned_data.get('first_name', '')
                user.last_name = form.cleaned_data.get('last_name', '')
                user.save()

                Profile.objects.create(
                    user=user,
                    role=form.cleaned_data.get('role'),
                    team=form.cleaned_data.get('team'),
                    phone_number=form.cleaned_data.get('phone_number'),
                    first_name=form.cleaned_data.get('first_name'),
                    last_name=form.cleaned_data.get('last_name'),
                    is_approved=True  # Approve immediately
                )
                
                messages.success(request, f"User '{user.username}' created successfully and is ready to use.")
                return redirect('approve')  # Redirect to user management page
            except IntegrityError:
                messages.error(request, 'This username is already taken. Please choose a different username.')
                return render(request, 'signup.html', {'form': form})
    else:
        form = SignUpForm()

    return render(request, 'signup.html', {'form': form})

def signup_view(request):
    if request.method == 'POST':
        user_form = SignUpForm(request.POST)
        profile_form = ProfileForm(request.POST)
        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save(commit=False)
            user.set_password(user_form.cleaned_data['password'])
            user.save()

            profile = profile_form.save(commit=False)
            profile.user = user
            profile.save()

            login(request, user)
            return redirect('profile')
    else:
        user_form = SignUpForm()
        profile_form = ProfileForm()

    return render(request, 'signup.html', {
        'user_form': user_form,
        'profile_form': profile_form
    })

@login_required
def export_sales_excel(request):
    """Download current user's sales as an Excel workbook."""
    sales_qs = Sale.objects.filter(user=request.user).order_by('-date')
    wb = Workbook()
    ws = wb.active
    ws.title = "Sales"
    # Header
    ws.append(["Date", "Property", "Developer", "Amount", "Status"])
    for s in sales_qs:
        ws.append([
            s.date.strftime('%Y-%m-%d') if s.date else '',
            getattr(s, 'property_name', getattr(s, 'property', '')),
            s.developer,
            float(s.amount),
            s.status,
        ])
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=sales_transactions.xlsx'
    wb.save(response)
    return response


@login_required
def export_top5_excel(request):
    """Export top 5 members by role to Excel. Query param role expected."""
    role = request.GET.get('role', 'Sales Agent')
    from django.contrib.auth.models import User
    from django.db.models import Sum
    # Aggregate sales per user
    sales = Sale.objects.filter(user__profile__role=role)
    sales_totals = sales.values('user').annotate(total=Sum('amount')).order_by('-total')[:5]
    user_ids = [item['user'] for item in sales_totals]
    users = User.objects.filter(id__in=user_ids)
    wb = Workbook()
    ws = wb.active
    ws.title = f"Top5 {role}"
    ws.append(["Name", "Role", "Total Sales"])
    for item in sales_totals:
        user = users.get(id=item['user'])
        ws.append([
            user.get_full_name() or user.username,
            role,
            float(item['total'] or 0)
        ])
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = f'attachment; filename=top5_{role.replace(" ", "_").lower()}.xlsx'
    wb.save(response)
    return response


def profile(request):
    # Get commission records (using Commission model instead of Sale)
    if request.user.is_superuser:
        commissions_list = Commission.objects.all().order_by('-date_released')
    else:
        commissions_list = Commission.objects.filter(agent=request.user).order_by('-date_released')
    
    # Get commission slips for the current user
    if request.user.is_superuser or request.user.profile.role == 'Sales Manager':
        commission_slips = CommissionSlip.objects.all().order_by('-date')
    else:
        commission_slips = CommissionSlip.objects.filter(
            sales_agent_name=request.user.get_full_name()
        ).order_by('-date')
    
    # Calculate commission summary from commission records
    total_commission_amount = commissions_list.aggregate(
        Sum('commission_amount'))['commission_amount__sum'] or Decimal('0')
    
    # Calculate commission count
    commission_count = commissions_list.count()
    
    # Paginate commissions (renamed from sales)
    page = request.GET.get('page', 1)
    paginator = Paginator(commissions_list, 10)  # Show 10 commissions per page
    try:
        paginated_commissions = paginator.page(page)
    except:
        paginated_commissions = paginator.page(1)
    
    # Add properties and developers to context
    properties = Property.objects.all().order_by('name')
    developers = Developer.objects.all().order_by('name')
    # Get commission data from receivables
    # Get commission data from receivables
    if request.user.is_superuser:
        commissions = Commission.objects.all().order_by('-date_released')
        tranche_records = TrancheRecord.objects.all()
    else:
        commissions = Commission.objects.filter(agent=request.user).order_by('-date_released')
        tranche_records = TrancheRecord.objects.filter(agent_name=request.user.get_full_name())

    total_commission_received = commissions.aggregate(Sum('commission_amount'))['commission_amount__sum'] or Decimal('0')

    # Calculate total expected commission from all tranches
    total_expected = Decimal('0')
    for record in tranche_records:
        total_expected += record.payments.aggregate(Sum('expected_amount'))['expected_amount__sum'] or Decimal('0')

    total_commission_remaining = total_expected - total_commission_received
    commission_count = commissions.count()

    # Get recent commissions for the table
    recent_commissions = commissions[:10]  # Get the 10 most recent

    context = {
        'commissions': paginated_commissions,
        'properties': properties,
        'developers': developers,
        'commission_slips': commission_slips,
        'total_commission_amount': total_commission_amount,
        'commission_count': commission_count,
        'total_commission_received': total_commission_received,
        'total_commission_remaining': total_commission_remaining,
        'recent_commissions': recent_commissions,
    }
    return render(request, 'profile.html', context)


@login_required(login_url='signin')
def edit_profile_view(request, profile_id=None):
    if profile_id:
        # Superuser is editing another user's profile
        if not request.user.is_superuser:
            messages.error(request, 'You do not have permission to perform this action.')
            return redirect('profile')
        profile = get_object_or_404(Profile, id=profile_id)
        user_to_edit = profile.user
        redirect_url = 'approve'
    else:
        # User is editing their own profile
        profile, created = Profile.objects.get_or_create(user=request.user)
        user_to_edit = request.user
        redirect_url = 'profile'

    if request.method == 'POST':
        # Update User model fields
        user_to_edit.first_name = request.POST.get('first_name', '')
        user_to_edit.last_name = request.POST.get('last_name', '')
        user_to_edit.email = request.POST.get('email', '')
        user_to_edit.save()

        # Handle profile image upload
        if request.FILES.get('image'):
            profile.image = request.FILES['image']

        # Update Profile model fields
        profile.phone_number = request.POST.get('phone_number', '')
        profile.address = request.POST.get('address', '')
        profile.save()

        messages.success(request, f"{user_to_edit.username}'s profile updated successfully!")
        return redirect(redirect_url)

    context = {
        'target_user': user_to_edit,
        'target_profile': profile
    }
    return render(request, 'edit_profile.html', context)


@login_required(login_url='signin')
@user_passes_test(lambda u: u.is_superuser)
def edit_user_profile(request, profile_id):
    """Allow a superuser to edit another user's profile."""
    profile = get_object_or_404(Profile, id=profile_id)
    user_obj = profile.user

    if request.method == 'POST':
        # Update User model fields
        user_obj.first_name = request.POST.get('first_name', '')
        user_obj.last_name = request.POST.get('last_name', '')
        user_obj.email = request.POST.get('email', '')
        user_obj.save()

        # Handle profile image upload
        if request.FILES.get('image'):
            profile.image = request.FILES['image']

        # Update Profile model fields
        profile.phone_number = request.POST.get('phone_number', '')
        profile.address = request.POST.get('address', '')
        profile.city = request.POST.get('city', '')
        profile.state = request.POST.get('state', '')
        profile.zip_code = request.POST.get('zip_code', '')
        profile.save()

        messages.success(request, f"{user_obj.username}'s profile updated successfully!")
        return redirect('approve')  # This is correct as the URL pattern is named 'approve'
    else:
        # For GET requests, show a confirmation page
        return render(request, 'edit_user_profile.html', {
            'target_user': user_obj,
            'target_profile': profile,
        })




@login_required(login_url='signin')
def approve_users_list(request):
    # Extended permission to include Sales Supervisor
    # Handle superuser without profile
    if request.user.is_superuser:
        user_profile = None
    else:
        try:
            user_profile = request.user.profile
            if user_profile.role not in ['Sales Manager', 'Sales Supervisor']:
                return HttpResponseForbidden("You don't have permission to view this page.")
        except Profile.DoesNotExist:
            return HttpResponseForbidden("You don't have permission to view this page.")

    context = {}

    if request.user.is_superuser or request.user.is_staff:
        # Superusers/Staff see all users and all stats
        base_query = Profile.objects.filter(is_approved=True)
        unapproved_accounts = Profile.objects.filter(is_approved=False)
        approved_accounts_list = base_query
        
        # Calculate stats for superuser/staff
        context['sales_managers_count'] = base_query.filter(role='Sales Manager').count()
        context['sales_supervisors_count'] = base_query.filter(role='Sales Supervisor').count()
        context['sales_agents_count'] = base_query.filter(role='Sales Agent').count()
        context['staff_count'] = User.objects.filter(is_staff=True).count()
        context['total_users_count'] = base_query.count()

    else:  # Sales Manager or Sales Supervisor
        # Managers/Supervisors see their team members
        user_team = user_profile.team
        base_query = Profile.objects.filter(is_approved=True, team=user_team)

        unapproved_accounts = Profile.objects.filter(
            is_approved=False,
            role__in=['Sales Supervisor', 'Sales Agent'],
            team=user_team
        )
        approved_accounts_list = base_query.filter(role__in=['Sales Supervisor', 'Sales Agent'])
        
        # Calculate stats for manager/supervisor
        context['sales_supervisors_count'] = base_query.filter(role='Sales Supervisor').count()
        context['sales_agents_count'] = base_query.filter(role='Sales Agent').count()
        context['total_users_count'] = base_query.count()

    # Common context for all roles
    active_teams = Team.objects.filter(is_active=True)

    # Pagination for approved accounts
    page = request.GET.get('page', 1)
    paginator = Paginator(approved_accounts_list, 10)
    try:
        approved_accounts = paginator.page(page)
    except:
        approved_accounts = paginator.page(1)

    # Add remaining items to context
    context.update({
        'unapproved_accounts': unapproved_accounts,
        'approved_accounts': approved_accounts,
        'teams': active_teams,
    })

    return render(request, 'approve.html', context)

@login_required
def approve_user(request, profile_id):
    # Get the profile to approve
    profile_to_approve = get_object_or_404(Profile, id=profile_id)
    
    # Check if user has permission to approve
    user_profile = request.user.profile
    can_approve = (
        request.user.is_superuser or  # Superuser can approve anyone
        (user_profile.role == 'Sales Manager' and  # Sales Manager can approve their team members
         user_profile.team == profile_to_approve.team and  # Must be same team
         profile_to_approve.role in ['Sales Agent', 'Sales Supervisor'])  # Can only approve agents and supervisors
    )
    
    if not can_approve:
        messages.error(request, "You don't have permission to approve this user.")
        return redirect('approve')
    
    if request.method == "POST":
        profile_to_approve.is_approved = True
        profile_to_approve.save()
        
        # Send approval email with updated message
        send_approval_email(request, profile_to_approve.user)
        messages.success(request, f'User {profile_to_approve.user.username} has been approved successfully.')
        return redirect('approve')
    else:
        # For GET requests, show a confirmation page
        return render(request, 'confirm_approve.html', {
            'profile': profile_to_approve
        })

@login_required
def reject_user(request, profile_id):
    # Get the profile to reject
    profile_to_reject = get_object_or_404(Profile, id=profile_id)
    
    # Check if user has permission to reject
    user_profile = request.user.profile
    can_reject = (
        request.user.is_superuser or  # Superuser can reject anyone
        (user_profile.role == 'Sales Manager' and  # Sales Manager can reject their team members
         user_profile.team == profile_to_reject.team and  # Must be same team
         profile_to_reject.role in ['Sales Agent', 'Sales Supervisor'])  # Can only reject agents and supervisors
    )
    
    if not can_reject:
        messages.error(request, "You don't have permission to reject this user.")
        return redirect('approve')
    
    # Store the username before deletion for the message
    username = profile_to_reject.user.username
    
    # Delete the user (this will cascade delete the profile as well)
    profile_to_reject.user.delete()
    
    messages.success(request, f"User {username} has been rejected.")
    return redirect('approve')


def commission(request):
    # Add your logic for the commission view here
    return render(request, 'commission.html')

def commission_slip_view(request, slip_id):
    # Fetch the commission slip by ID
    slip = get_object_or_404(CommissionSlip, id=slip_id)
    return render(request, 'commission.html', {'slip': slip})

@login_required(login_url='signin')
def create_commission_slip(request):
    if request.method == 'POST':
        slip_form = CommissionSlipForm(request.POST)
        if slip_form.is_valid():
            slip = slip_form.save(commit=False)
            slip.created_by = request.user
            slip.created_at = timezone.now()
            
            # Get form data
            total_selling_price = Decimal(request.POST.get('total_selling_price', '0'))
            commission_rate = Decimal(request.POST.get('commission_rate', '0'))
            particulars = request.POST.get('particulars[]', 'FULL COMM')
            partial_percentage = Decimal(request.POST.get('partial_percentage', '100'))
            incentive_amount = Decimal(request.POST.get('incentive_amount', '0'))
            cash_advance = Decimal(request.POST.get('cash_advance', '0'))
            withholding_tax_rate = Decimal(request.POST.get('withholding_tax_rate', '10.00'))
            
            # Calculate cash advance tax (10%)
            cash_advance_tax = cash_advance * Decimal('0.10')
            net_cash_advance = cash_advance - cash_advance_tax
            
            # Calculate adjusted total
            adjusted_total = total_selling_price - net_cash_advance
            
            # Calculate base commission
            base_commission = adjusted_total * (commission_rate / 100) 
            
            # Apply partial percentage if applicable
            if particulars == 'PARTIAL COMM':
                base_commission = base_commission * (partial_percentage / 100)
            
            # Calculate gross commission
            gross_commission = base_commission
            if particulars == 'INCENTIVES':
                gross_commission = base_commission + incentive_amount
            
            # Calculate tax
            tax_rate = withholding_tax_rate / 100
            withholding_tax = gross_commission * tax_rate
            net_commission = gross_commission - withholding_tax
            
            # Get sales manager data
            sales_manager_name = request.POST.get('sales_manager_name')
            manager_commission_rate = Decimal(request.POST.get('manager_commission_rate', '0'))

            # Save the slip with all calculated values
            slip.total_selling_price = total_selling_price
            slip.cash_advance = cash_advance
            slip.cash_advance_tax = cash_advance_tax
            slip.incentive_amount = incentive_amount
            slip.withholding_tax_rate = withholding_tax_rate
            slip.sales_manager_name = sales_manager_name
            slip.manager_commission_rate = manager_commission_rate
            slip.save()

            # Create agent commission detail
            CommissionDetail.objects.create(
                slip=slip,
                position=request.POST.get('position[]', 'Sales Agent'),
                particulars=particulars,
                commission_rate=commission_rate,
                base_commission=base_commission,
                gross_commission=gross_commission,
                withholding_tax=withholding_tax,
                net_commission=net_commission,
                agent_name=request.POST.get('sales_agent_name'),
                partial_percentage=partial_percentage,
                withholding_tax_rate=withholding_tax_rate
            )

            # Create manager commission detail if applicable
            if manager_commission_rate > 0 and sales_manager_name:
                manager_base_commission = total_selling_price * (manager_commission_rate / 100)
                if particulars == 'PARTIAL COMM':
                    manager_base_commission = manager_base_commission * (partial_percentage / 100)
                
                manager_gross_commission = manager_base_commission
                manager_withholding_tax = manager_gross_commission * tax_rate
                manager_net_commission = manager_gross_commission - manager_withholding_tax

                CommissionDetail.objects.create(
                    slip=slip,
                    position='Sales Manager',
                    particulars=particulars,
                    commission_rate=manager_commission_rate,
                    base_commission=manager_base_commission,
                    gross_commission=manager_gross_commission,
                    withholding_tax=manager_withholding_tax,
                    net_commission=manager_net_commission,
                    agent_name=sales_manager_name,
                    partial_percentage=partial_percentage,
                    withholding_tax_rate=withholding_tax_rate
                )

            messages.success(request, "Commission slip created successfully!")
            return redirect('commission_history')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        slip_form = CommissionSlipForm()

    # Get users based on permissions
    if request.user.is_superuser or request.user.is_staff:
        # Superusers and staff can see all approved users from all teams
        sales_agents = User.objects.filter(
            profile__is_approved=True, profile__role='Sales Agent'
        ).select_related('profile', 'profile__team').order_by('username')
        sales_managers = User.objects.filter(
            profile__is_approved=True, profile__role='Sales Manager'
        ).select_related('profile', 'profile__team').order_by('username')
    else:
        # Regular users can only see their team members
        user_team = request.user.profile.team
        sales_agents = User.objects.filter(
            profile__is_approved=True,
            profile__team=user_team,
            profile__role='Sales Agent'
        ).select_related('profile', 'profile__team').order_by('username')
        sales_managers = User.objects.filter(
            profile__is_approved=True,
            profile__team=user_team,
            profile__role='Sales Manager'
        ).select_related('profile', 'profile__team').order_by('username')

    # Get all properties for the dropdown
    properties = Property.objects.all().order_by('name')
    
    context = {
        'slip_form': slip_form,
        'sales_agents': sales_agents,
        'sales_managers': sales_managers,
        'properties': properties,
        'user_is_staff': request.user.is_staff,
        'user_is_superuser': request.user.is_superuser
    }
    return render(request, 'create_commission_slip.html', context)

def commission_history(request):
    if not request.user.is_authenticated:
        return redirect('signin')

    # Import Q at the top of the function to avoid UnboundLocalError
    from django.db.models import Q

    # Get search parameters
    search_agent = request.GET.get('search_agent', '')
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')
    # Extra filter parameters
    team_filter = request.GET.get('team', '')
    user_filter = request.GET.get('user', '')
    year_filter = request.GET.get('year', '')
    month_filter = request.GET.get('month', '')
    developer_filter = request.GET.get('developer', '')
    property_filter = request.GET.get('property', '')
    type_filter = request.GET.get('type', '')

    # Query CommissionSlip
    commission_slips = CommissionSlip.objects.all().order_by('-date')
    # Query CommissionSlip3
    commission_slips3 = CommissionSlip3.objects.all().order_by('-date')

    # Apply filters to both
    if search_agent:
        commission_slips = commission_slips.filter(
            Q(sales_agent_name__icontains=search_agent) |
            Q(buyer_name__icontains=search_agent) |
            Q(project_name__icontains=search_agent)
        )
        commission_slips3 = commission_slips3.filter(
            Q(sales_agent_name__icontains=search_agent) |
            Q(supervisor_name__icontains=search_agent) |
            Q(buyer_name__icontains=search_agent) |
            Q(project_name__icontains=search_agent)
        )

    if start_date:
        commission_slips = commission_slips.filter(date__gte=start_date)
        commission_slips3 = commission_slips3.filter(date__gte=start_date)
    if end_date:
        commission_slips = commission_slips.filter(date__lte=end_date)
        commission_slips3 = commission_slips3.filter(date__lte=end_date)

    # Apply additional pre-permission filters
    if year_filter:
        commission_slips = commission_slips.filter(date__year=year_filter)
        commission_slips3 = commission_slips3.filter(date__year=year_filter)
    if month_filter:
        commission_slips = commission_slips.filter(date__month=month_filter)
        commission_slips3 = commission_slips3.filter(date__month=month_filter)
    if developer_filter:
        # Filter by developer name using Property model relationship
        from .models import Property
        
        # Get all properties that belong to the selected developer
        developer_properties = Property.objects.filter(
            developer__name__icontains=developer_filter
        ).values_list('name', flat=True)
        
        if developer_properties:
            # Filter commission slips by matching project names with developer's properties
            property_query = Q()
            for prop_name in developer_properties:
                property_query |= Q(project_name__icontains=prop_name)
            commission_slips = commission_slips.filter(property_query)
            commission_slips3 = commission_slips3.filter(property_query)
        else:
            # If no properties found for this developer, return empty querysets
            commission_slips = commission_slips.none()
            commission_slips3 = commission_slips3.none()
    if property_filter:
        commission_slips = commission_slips.filter(project_name__icontains=property_filter)
        commission_slips3 = commission_slips3.filter(project_name__icontains=property_filter)
    # Apply type filter using available fields
    if type_filter == 'regular':
        commission_slips = commission_slips.filter(is_full_breakdown=False)
        commission_slips3 = commission_slips3.none()
    elif type_filter == 'management':
        commission_slips = commission_slips.filter(is_full_breakdown=True)
        commission_slips3 = commission_slips3.none()
    elif type_filter == 'supervisor_agent':
        commission_slips = commission_slips.none()
        # keep commission_slips3 as is

    # Filter based on user role and permissions
    if request.user.is_superuser or request.user.is_staff:
        # Superusers and staff can see all commission slips
        pass
    elif request.user.profile.role == 'Sales Manager':
        # Sales Managers can see their team's slips, slips they created, and slips created by superusers/staff
        user_team = request.user.profile.team
        commission_slips = commission_slips.filter(
            Q(created_by=request.user) |
            Q(sales_agent_name=request.user.get_full_name()) |
            Q(created_by__profile__team=user_team) |
            Q(created_by__is_superuser=True) |
            Q(created_by__is_staff=True)
        )
        commission_slips3 = commission_slips3.filter(
            Q(created_by=request.user) |
            Q(sales_agent_name=request.user.get_full_name()) |
            Q(supervisor_name=request.user.get_full_name()) |
            Q(created_by__profile__team=user_team) |
            Q(created_by__is_superuser=True) |
            Q(created_by__is_staff=True)
        )
    else:
        # Regular users can only see their own commission slips
        commission_slips = commission_slips.filter(
            Q(sales_agent_name=request.user.get_full_name()) |
            Q(created_by=request.user)
        )
        commission_slips3 = commission_slips3.filter(
            Q(sales_agent_name=request.user.get_full_name()) |
            Q(supervisor_name=request.user.get_full_name()) |
            Q(created_by=request.user)
        )

    # Apply user/team filters post-permission scoping
    if user_filter:
        try:
            selected_user = User.objects.get(id=user_filter)
            selected_name = selected_user.get_full_name()
            commission_slips = commission_slips.filter(Q(sales_agent_name=selected_name) | Q(created_by=selected_user))
            commission_slips3 = commission_slips3.filter(
                Q(sales_agent_name=selected_name) | Q(supervisor_name=selected_name) | Q(created_by=selected_user)
            )
        except User.DoesNotExist:
            pass
    if team_filter and (request.user.is_superuser or request.user.is_staff):
        try:
            selected_team = Team.objects.get(id=team_filter)
            team_members = User.objects.filter(profile__team=selected_team, is_active=True)
            member_names = [m.get_full_name() for m in team_members if m.get_full_name()]
            commission_slips = commission_slips.filter(
                Q(created_by__profile__team=selected_team) | Q(sales_agent_name__in=member_names)
            )
            commission_slips3 = commission_slips3.filter(
                Q(created_by__profile__team=selected_team) | Q(sales_agent_name__in=member_names) | Q(supervisor_name__in=member_names)
            )
        except Team.DoesNotExist:
            pass

    # Initialize all commission variables
    total_gross_commission = 0
    sales_agents_commission = 0
    supervisors_commission = 0
    managers_commission = 0
    operations_commission = 0
    cofounder_commission = 0
    founder_commission = 0
    funds_commission = 0
    user_commission = 0  # For regular users
    sales_team_total = 0  # For total breakdown
    management_team_total = 0  # For total breakdown
    
    # Get commission details based on user permissions
    if request.user.is_superuser or request.user.is_staff:
        # For superusers and staff, show commissions from filtered slips
        commission_details = CommissionDetail.objects.filter(slip__in=commission_slips)
        commission_details3 = CommissionDetail3.objects.filter(slip__in=commission_slips3)
        
        # Calculate role-based commissions from CommissionDetail
        sales_agents_commission = commission_details.filter(
            position='Sales Agent'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        supervisors_commission = commission_details.filter(
            position='Sales Supervisor'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        managers_commission = commission_details.filter(
            position='Sales Manager'
        ).exclude(slip__source='full_breakdown').aggregate(total=models.Sum('gross_commission'))['total'] or 0

  
        operations_commission = commission_details.filter(
            position='Operation Manager'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        cofounder_commission = commission_details.filter(
            position='Co-Founder'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        founder_commission = commission_details.filter(
            position='Founder'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        funds_commission = commission_details.filter(
            position='Funds'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        # Add commissions from CommissionDetail3
        sales_agents_commission += commission_details3.filter(
            position='Sales Agent'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        supervisors_commission += commission_details3.filter(
            position='Sales Supervisor'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        managers_commission += commission_details3.filter(
            position='Sales Manager'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        # Calculate team totals - now "Total" includes all commissions
        sales_team_total = sales_agents_commission + supervisors_commission + managers_commission + operations_commission + cofounder_commission + founder_commission + funds_commission
        management_team_total =  operations_commission + cofounder_commission + founder_commission + funds_commission
        
        # Calculate grand total (all commissions)
        total_gross_commission = sales_team_total
        
    elif request.user.profile.role == 'Sales Manager':
        # For Sales Managers, show team commissions based on filtered slips
        commission_details = CommissionDetail.objects.filter(slip__in=commission_slips)
        commission_details3 = CommissionDetail3.objects.filter(slip__in=commission_slips3)
        
        # Calculate role-based commissions from filtered commission details
        sales_agents_commission = commission_details.filter(
            position='Sales Agent'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        supervisors_commission = commission_details.filter(
            position='Sales Supervisor'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        managers_commission = commission_details.filter(
            position='Sales Manager'
        ).exclude(slip__source='full_breakdown').exclude(slip__source='manual_breakdown').aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        # Add commissions from CommissionDetail3
        sales_agents_commission += commission_details3.filter(
            position='Sales Agent'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        supervisors_commission += commission_details3.filter(
            position='Sales Supervisor'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        managers_commission += commission_details3.filter(
            position='Sales Manager'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        # For management team, get all other positions
        operations_commission = commission_details.filter(
            position='Operation Manager'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        cofounder_commission = commission_details.filter(
            position='Co-Founder'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        founder_commission = commission_details.filter(
            position='Founder'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        funds_commission = commission_details.filter(
            position='Funds'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        management_team_total = operations_commission + cofounder_commission + founder_commission + funds_commission
        
        # Calculate team totals - for Sales Manager, only include sales team
        sales_team_total = sales_agents_commission + supervisors_commission + managers_commission
        
        # Calculate grand total (only sales team for Sales Manager)
        total_gross_commission = sales_team_total
        
    elif request.user.profile.role == 'Sales Agent':
        # For Sales Agents, show ONLY Sales Agent commissions
        commission_details = CommissionDetail.objects.filter(slip__in=commission_slips)
        commission_details3 = CommissionDetail3.objects.filter(slip__in=commission_slips3)
        
        # Calculate ONLY Sales Agent commissions
        sales_agents_commission = commission_details.filter(
            position='Sales Agent'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        # Add Sales Agent commissions from CommissionDetail3
        sales_agents_commission += commission_details3.filter(
            position='Sales Agent'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        # Set other commissions to 0 for Sales Agents
        supervisors_commission = 0
        managers_commission = 0
        
        # Calculate total (only Sales Agent commissions)
        total_gross_commission = sales_agents_commission
        
    elif request.user.profile.role == 'Sales Supervisor':
        # For Sales Supervisors, show ONLY Agent and Supervisor commissions (exclude managers)
        commission_details = CommissionDetail.objects.filter(slip__in=commission_slips)
        commission_details3 = CommissionDetail3.objects.filter(slip__in=commission_slips3)
        
        # Calculate ONLY Sales Agent and Supervisor commissions
        sales_agents_commission = commission_details.filter(
            position='Sales Agent'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        supervisors_commission = commission_details.filter(
            position='Sales Supervisor'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        # Add commissions from CommissionDetail3
        sales_agents_commission += commission_details3.filter(
            position='Sales Agent'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        supervisors_commission += commission_details3.filter(
            position='Sales Supervisor'
        ).aggregate(total=models.Sum('gross_commission'))['total'] or 0
        
        # Set manager commissions to 0 for Sales Supervisors
        managers_commission = 0
        
        # Calculate total (only agents and supervisors for Sales Supervisor)
        total_gross_commission = sales_agents_commission + supervisors_commission
        
    else:
        # For other regular users, only show their commissions
        # Get commission details where they are specifically mentioned
        commission_details = CommissionDetail.objects.filter(
            Q(slip__sales_agent_name=request.user.get_full_name()) &
            Q(position=request.user.profile.role)  # Only get their specific role's commission
        )
        commission_details3 = CommissionDetail3.objects.filter(
            (Q(slip__sales_agent_name=request.user.get_full_name()) & Q(position='Sales Agent')) |
            (Q(slip__supervisor_name=request.user.get_full_name()) & Q(position='Sales Supervisor'))
        )
        
        # Calculate user's total commission from their specific role's commission
        user_commission = (
            commission_details.aggregate(total=models.Sum('gross_commission'))['total'] or 0
        ) + (
            commission_details3.aggregate(total=models.Sum('gross_commission'))['total'] or 0
        )
        total_gross_commission = user_commission

    # Count commission types
    regular_commission_count = commission_slips.filter(is_full_breakdown=False).count()
    management_commission_count = commission_slips.filter(is_full_breakdown=True).count()
    supervisor_agent_commission_count = commission_slips3.count()

    # Create a list of all slips with their type
    all_slips = []
    
    # Add regular commission slips
    for slip in commission_slips:
        slip.slip_type = 'regular'
        all_slips.append(slip)
    
    # Add supervisor-agent commission slips
    for slip in commission_slips3:
        slip.slip_type = 'supervisor_agent'
        all_slips.append(slip)

    # Sort all slips by date (descending)
    all_slips.sort(key=lambda slip: slip.date if slip.date else slip.created_at, reverse=True)

    # Paginate merged slips
    page = request.GET.get('page', 1)
    paginator = Paginator(all_slips, 10)  # Show 10 slips per page
    try:
        paginated_slips = paginator.page(page)
    except:
        paginated_slips = paginator.page(1)

    # Get team members based on user role
    # Check if user has a profile first
    try:
        user_profile = request.user.profile
    except:
        user_profile = None
    
    if user_profile and user_profile.role == 'Sales Manager':
        # Sales Managers only see their own team members
        user_team = request.user.profile.team
        team_members = User.objects.filter(
            is_active=True,
            profile__team=user_team,
            profile__role__in=['Sales Agent', 'Sales Supervisor', 'Sales Manager']
        ).select_related('profile')
        
        # Calculate individual commission totals for each team member
        for member in team_members:
            member_name = member.get_full_name()
            
            # Skip if member doesn't have a profile
            if not hasattr(member, 'profile') or not member.profile:
                member.total_commission = 0
                continue
            
            # Get commission details for this specific team member
            member_commission_details = CommissionDetail.objects.filter(
                slip__in=commission_slips,
                slip__sales_agent_name=member_name,
                position=member.profile.role
            )
            if member.profile.role == 'Sales Manager':
                member_commission_details = member_commission_details.exclude(slip__source='full_breakdown')
            
            member_commission_details3 = CommissionDetail3.objects.filter(
                slip__in=commission_slips3
            ).filter(
                Q(slip__sales_agent_name=member_name, position='Sales Agent') |
                Q(slip__supervisor_name=member_name, position='Sales Supervisor') |
                Q(slip__manager_name=member_name, position='Sales Manager')
            )
            
            # Calculate total commission for this member
            member_total = (
                member_commission_details.aggregate(total=models.Sum('gross_commission'))['total'] or 0
            ) + (
                member_commission_details3.aggregate(total=models.Sum('gross_commission'))['total'] or 0
            )
            
            # Attach the commission total to the member object (convert to float for JSON serialization)
            member.total_commission = float(member_total) if member_total else 0
            
    elif user_profile and user_profile.role == 'Sales Agent':
        # Sales Agents see ONLY Sales Agent team members
        user_team = request.user.profile.team
        team_members = User.objects.filter(
            is_active=True,
            profile__team=user_team,
            profile__role='Sales Agent'
        ).select_related('profile')
        
        # Calculate individual commission totals for each team member
        for member in team_members:
            member_name = member.get_full_name()
            
            # Skip if member doesn't have a profile
            if not hasattr(member, 'profile') or not member.profile:
                member.total_commission = 0
                continue
            
            # Get commission details for this specific team member
            member_commission_details = CommissionDetail.objects.filter(
                slip__in=commission_slips,
                slip__sales_agent_name=member_name,
                position=member.profile.role
            )
            if member.profile.role == 'Sales Manager':
                member_commission_details = member_commission_details.exclude(slip__source='full_breakdown')
            
            member_commission_details3 = CommissionDetail3.objects.filter(
                slip__in=commission_slips3
            ).filter(
                Q(slip__sales_agent_name=member_name, position='Sales Agent') |
                Q(slip__supervisor_name=member_name, position='Sales Supervisor') |
                Q(slip__manager_name=member_name, position='Sales Manager')
            )
            
            # Calculate total commission for this member
            member_total = (
                member_commission_details.aggregate(total=models.Sum('gross_commission'))['total'] or 0
            ) + (
                member_commission_details3.aggregate(total=models.Sum('gross_commission'))['total'] or 0
            )
            
            # Attach the commission total to the member object (convert to float for JSON serialization)
            member.total_commission = float(member_total) if member_total else 0
            
    elif user_profile and user_profile.role == 'Sales Supervisor':
        # Sales Supervisors see ONLY Sales Agent and Sales Supervisor team members
        user_team = request.user.profile.team
        team_members = User.objects.filter(
            is_active=True,
            profile__team=user_team,
            profile__role__in=['Sales Agent', 'Sales Supervisor']
        ).select_related('profile')
        
        # Calculate individual commission totals for each team member
        for member in team_members:
            member_name = member.get_full_name()
            
            # Skip if member doesn't have a profile
            if not hasattr(member, 'profile') or not member.profile:
                member.total_commission = 0
                continue
            
            # Get commission details for this specific team member
            member_commission_details = CommissionDetail.objects.filter(
                slip__in=commission_slips,
                slip__sales_agent_name=member_name,
                position=member.profile.role
            )
            if member.profile.role == 'Sales Manager':
                member_commission_details = member_commission_details.exclude(slip__source='full_breakdown')
            
            member_commission_details3 = CommissionDetail3.objects.filter(
                slip__in=commission_slips3
            ).filter(
                Q(slip__sales_agent_name=member_name, position='Sales Agent') |
                Q(slip__supervisor_name=member_name, position='Sales Supervisor') |
                Q(slip__manager_name=member_name, position='Sales Manager')
            )
            
            # Calculate total commission for this member
            member_total = (
                member_commission_details.aggregate(total=models.Sum('gross_commission'))['total'] or 0
            ) + (
                member_commission_details3.aggregate(total=models.Sum('gross_commission'))['total'] or 0
            )
            
            # Attach the commission total to the member object (convert to float for JSON serialization)
            member.total_commission = float(member_total) if member_total else 0
    else:
        # For superuser/staff, show all active users with commission calculations
        team_members = User.objects.filter(is_active=True).select_related('profile')
        
        # Calculate individual commission totals for each team member (same logic as Sales Manager)
        for member in team_members:
            member_name = member.get_full_name()
            
            # Skip if member doesn't have a profile
            if not hasattr(member, 'profile') or not member.profile:
                member.total_commission = 0
                continue
            
            # Get commission details for this specific team member
            member_commission_details = CommissionDetail.objects.filter(
                slip__in=commission_slips,
                slip__sales_agent_name=member_name,
                position=member.profile.role
            )
            if member.profile.role == 'Sales Manager':
                member_commission_details = member_commission_details.exclude(slip__source='full_breakdown')
            
            member_commission_details3 = CommissionDetail3.objects.filter(
                slip__in=commission_slips3
            ).filter(
                Q(slip__sales_agent_name=member_name, position='Sales Agent') |
                Q(slip__supervisor_name=member_name, position='Sales Supervisor') |
                Q(slip__manager_name=member_name, position='Sales Manager')
            )
            
            # Calculate total commission for this member
            member_total = (
                member_commission_details.aggregate(total=models.Sum('gross_commission'))['total'] or 0
            ) + (
                member_commission_details3.aggregate(total=models.Sum('gross_commission'))['total'] or 0
            )
            
            # Attach the commission total to the member object (convert to float for JSON serialization)
            member.total_commission = float(member_total) if member_total else 0

    # Attach details and agent_role for each slip
    for slip in paginated_slips:
        if slip.slip_type == 'supervisor_agent':  # CommissionSlip3
            setattr(slip, 'custom_details', CommissionDetail3.objects.filter(slip=slip))
            # For agent role, use the agent's role if possible
            slip.agent_role = 'Sales Agent'
        else:  # CommissionSlip
            setattr(slip, 'custom_details', CommissionDetail.objects.filter(slip=slip))
            detail = slip.custom_details.first()
            if detail:
                slip.agent_role = detail.position
            else:
                # Try to find the user by their full name
                name_parts = slip.sales_agent_name.split()
                agent = User.objects.filter(
                    Q(first_name__in=name_parts) & Q(last_name__in=name_parts)
                ).first()
                if agent and hasattr(agent, 'profile'):
                    slip.agent_role = agent.profile.role
                else:
                    slip.agent_role = "Unknown Role"

    # Calculate total slips count
    total_slips = regular_commission_count + management_commission_count + supervisor_agent_commission_count

    # Build dropdown data
    all_teams = Team.objects.filter(is_active=True).order_by('name') if (request.user.is_superuser or request.user.is_staff) else []
    all_users = User.objects.filter(is_active=True).order_by('first_name', 'last_name') if (request.user.is_superuser or request.user.is_staff) else []
    # Build available years without union().dates() (not supported with annotate/union)
    years_slips = list(commission_slips.dates('date', 'year', order='DESC'))
    years_slips3 = list(commission_slips3.dates('date', 'year', order='DESC'))
    years_set = {d.year for d in years_slips} | {d.year for d in years_slips3}
    years_list = sorted(list(years_set), reverse=True)
    months_list = [(i, datetime(2000, i, 1).strftime('%B')) for i in range(1, 13)]
    # Get properties from project names and developers from Developer model
    from .models import Developer
    dev1 = list(commission_slips.values_list('project_name', flat=True))
    dev2 = list(commission_slips3.values_list('project_name', flat=True))
    all_properties = sorted(list({d for d in dev1 + dev2 if d}))
    # Get developers from Developer model
    all_developers = list(Developer.objects.values_list('name', flat=True).order_by('name'))

    # Calculate monthly trends for all roles
    monthly_trends = {'labels': [], 'data': []}
    
    # Get monthly commission data based on user role
    if request.user.is_superuser or request.user.is_staff:
        # For superusers, get all commission data by month
        monthly_data = CommissionDetail.objects.filter(
            slip__in=commission_slips,
            slip__date__isnull=False
        ).annotate(
            month=TruncMonth('slip__date')
        ).values('month').annotate(
            total=models.Sum('gross_commission')
        ).order_by('month')
        
        # Add CommissionDetail3 data
        monthly_data3 = CommissionDetail3.objects.filter(
            slip__in=commission_slips3,
            slip__date__isnull=False
        ).annotate(
            month=TruncMonth('slip__date')
        ).values('month').annotate(
            total=models.Sum('gross_commission')
        ).order_by('month')
        
        # Combine monthly data
        monthly_combined = {}
        for item in monthly_data:
            month = item['month']
            monthly_combined[month] = monthly_combined.get(month, 0) + (item['total'] or 0)
        
        for item in monthly_data3:
            month = item['month']
            monthly_combined[month] = monthly_combined.get(month, 0) + (item['total'] or 0)
        
        # Sort by month and prepare chart data
        sorted_months = sorted(monthly_combined.keys())
        monthly_trends['labels'] = [month.strftime('%b %Y') for month in sorted_months]
        monthly_trends['data'] = [float(monthly_combined[month]) for month in sorted_months]
        
    elif request.user.profile.role == 'Sales Manager':
        # For Sales Managers, get team commission data by month
        monthly_data = CommissionDetail.objects.filter(
            slip__in=commission_slips,
            position__in=['Sales Agent', 'Sales Supervisor', 'Sales Manager'],
            slip__date__isnull=False
        ).annotate(
            month=TruncMonth('slip__date')
        ).values('month').annotate(
            total=models.Sum('gross_commission')
        ).order_by('month')
        
        monthly_data3 = CommissionDetail3.objects.filter(
            slip__in=commission_slips3,
            position__in=['Sales Agent', 'Sales Supervisor', 'Sales Manager'],
            slip__date__isnull=False
        ).annotate(
            month=TruncMonth('slip__date')
        ).values('month').annotate(
            total=models.Sum('gross_commission')
        ).order_by('month')
        
        # Combine monthly data
        monthly_combined = {}
        for item in monthly_data:
            month = item['month']
            monthly_combined[month] = monthly_combined.get(month, 0) + (item['total'] or 0)
        
        for item in monthly_data3:
            month = item['month']
            monthly_combined[month] = monthly_combined.get(month, 0) + (item['total'] or 0)
        
        # Sort by month and prepare chart data
        sorted_months = sorted(monthly_combined.keys())
        monthly_trends['labels'] = [month.strftime('%b %Y') for month in sorted_months]
        monthly_trends['data'] = [float(monthly_combined[month]) for month in sorted_months]
        
    elif request.user.profile.role == 'Sales Agent':
        # For Sales Agents, get only agent commission data by month
        monthly_data = CommissionDetail.objects.filter(
            slip__in=commission_slips,
            position='Sales Agent',
            slip__date__isnull=False
        ).annotate(
            month=TruncMonth('slip__date')
        ).values('month').annotate(
            total=models.Sum('gross_commission')
        ).order_by('month')
        
        monthly_data3 = CommissionDetail3.objects.filter(
            slip__in=commission_slips3,
            position='Sales Agent',
            slip__date__isnull=False
        ).annotate(
            month=TruncMonth('slip__date')
        ).values('month').annotate(
            total=models.Sum('gross_commission')
        ).order_by('month')
        
        # Combine monthly data
        monthly_combined = {}
        for item in monthly_data:
            month = item['month']
            monthly_combined[month] = monthly_combined.get(month, 0) + (item['total'] or 0)
        
        for item in monthly_data3:
            month = item['month']
            monthly_combined[month] = monthly_combined.get(month, 0) + (item['total'] or 0)
        
        # Sort by month and prepare chart data
        sorted_months = sorted(monthly_combined.keys())
        monthly_trends['labels'] = [month.strftime('%b %Y') for month in sorted_months]
        monthly_trends['data'] = [float(monthly_combined[month]) for month in sorted_months]
        
    elif request.user.profile.role == 'Sales Supervisor':
        # For Sales Supervisors, get agent and supervisor commission data by month
        monthly_data = CommissionDetail.objects.filter(
            slip__in=commission_slips,
            position__in=['Sales Agent', 'Sales Supervisor'],
            slip__date__isnull=False
        ).annotate(
            month=TruncMonth('slip__date')
        ).values('month').annotate(
            total=models.Sum('gross_commission')
        ).order_by('month')
        
        monthly_data3 = CommissionDetail3.objects.filter(
            slip__in=commission_slips3,
            position__in=['Sales Agent', 'Sales Supervisor'],
            slip__date__isnull=False
        ).annotate(
            month=TruncMonth('slip__date')
        ).values('month').annotate(
            total=models.Sum('gross_commission')
        ).order_by('month')
        
        # Combine monthly data
        monthly_combined = {}
        for item in monthly_data:
            month = item['month']
            monthly_combined[month] = monthly_combined.get(month, 0) + (item['total'] or 0)
        
        for item in monthly_data3:
            month = item['month']
            monthly_combined[month] = monthly_combined.get(month, 0) + (item['total'] or 0)
        
        # Sort by month and prepare chart data
        sorted_months = sorted(monthly_combined.keys())
        monthly_trends['labels'] = [month.strftime('%b %Y') for month in sorted_months]
        monthly_trends['data'] = [float(monthly_combined[month]) for month in sorted_months]
    
    # Handle AJAX requests for chart data
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        from django.http import JsonResponse
        return JsonResponse({
            'total_gross_commission': float(total_gross_commission),
            'sales_agents_commission': float(sales_agents_commission),
            'supervisors_commission': float(supervisors_commission),
            'managers_commission': float(managers_commission),
            'operations_commission': float(operations_commission),
            'cofounder_commission': float(cofounder_commission),
            'founder_commission': float(founder_commission),
            'funds_commission': float(funds_commission),
            'sales_team_total': float(sales_team_total),
            'management_team_total': float(management_team_total),
            'user_commission': float(user_commission),
            'monthly_trends': monthly_trends,
        })

    context = {
        'commission_slips': paginated_slips,
        'search_agent': search_agent,
        'start_date': start_date,
        'end_date': end_date,
        'is_superuser': request.user.is_superuser,
        'regular_commission_count': regular_commission_count,
        'management_commission_count': management_commission_count,
        'supervisor_agent_commission_count': supervisor_agent_commission_count,
        'total_slips': total_slips,
        'team_members': team_members,
        'total_gross_commission': float(total_gross_commission) if total_gross_commission else 0,
        # Role-based commission totals
        'sales_agents_commission': float(sales_agents_commission) if sales_agents_commission else 0,
        'supervisors_commission': float(supervisors_commission) if supervisors_commission else 0,
        'managers_commission': float(managers_commission) if managers_commission else 0,
        'operations_commission': float(operations_commission) if operations_commission else 0,
        'cofounder_commission': float(cofounder_commission) if cofounder_commission else 0,
        'founder_commission': float(founder_commission) if founder_commission else 0,
        'funds_commission': float(funds_commission) if funds_commission else 0,
        # Team totals
        'sales_team_total': float(sales_team_total) if sales_team_total else 0,
        'management_team_total': float(management_team_total) if management_team_total else 0,
        'management_commission': float(management_team_total) if management_team_total else 0,  # Add this for chart compatibility
        # User-specific commission
        'user_commission': float(user_commission) if user_commission else 0,
        # Filter dropdowns
        'all_teams': all_teams,
        'all_users': all_users,
        'available_years': years_list,
        'available_months': months_list,
        'all_developers': all_developers,
        'all_properties': all_properties,
        'selected_team': team_filter,
        'selected_user': user_filter,
        'selected_year': year_filter,
        'selected_month': month_filter,
        'selected_developer': developer_filter,
        'selected_property': property_filter,
        'selected_type': type_filter,
        # Monthly trends data for charts
        'monthly_trends': json.dumps(monthly_trends),
    }
    return render(request, 'commission_history.html', context)

def commission_view(request, slip_id=None):
    if not request.user.is_authenticated:
        return redirect('signin')

    if slip_id:
        slip = get_object_or_404(CommissionSlip, id=slip_id)
        
        # For superusers, allow viewing all commission slips
        if request.user.is_superuser:
            details = CommissionDetail.objects.filter(slip=slip)
            all_slips = CommissionSlip.objects.all().order_by('-id')

            # Calculate totals
            total_gross = sum(detail.gross_commission for detail in details)
            total_tax = sum(detail.withholding_tax for detail in details)
            total_net = sum(detail.net_commission for detail in details)

            return render(request, 'commission.html', {
                'slip': slip,
                'details': details,
                'total_gross': total_gross,
                'total_tax': total_tax,
                'total_net': total_net,
                'all_slips': all_slips,
                'viewing_as_creator': True
            })

        # For regular agents, supervisors, and managers
        if request.user.profile.role in ['Sales Agent', 'Sales Supervisor', 'Sales Manager']:
            # Check if the user is the creator or the slip belongs to them
            is_creator = slip.created_by == request.user
            is_agent = slip.sales_agent_name == request.user.get_full_name()
            
            # Check if the user is named in any commission details (for managers)
            user_full_name = request.user.get_full_name()
            is_in_details = CommissionDetail.objects.filter(
                slip=slip, 
                agent_name=user_full_name
            ).exists()
            
            if not (is_creator or is_agent or is_in_details):
                messages.error(request, 'You do not have permission to view this slip.')
                return redirect('commission_history')
            
            # Get all details for this slip
            details = CommissionDetail.objects.filter(slip=slip)
            
            # For Sales Managers, filter out management positions
            if request.user.profile.role == 'Sales Manager':
                # Sales Managers can only see sales-related positions (hide management positions)
                management_positions = ['Operations Manager', 'Operation Manager', 'Co-Founder', 'Cofounder', 'Co Founder', 'Founder', 'Funds']
                details = details.exclude(position__in=management_positions)
            elif is_creator and not is_agent and not is_in_details:
                # Filter details to show only those matching the sales agent's position
                agent_details = details.filter(agent_name=slip.sales_agent_name)
                if agent_details.exists():
                    details = agent_details
            elif is_in_details and not is_agent:
                # Show their own commission details when they are named in the details
                details = details.filter(agent_name=user_full_name)
            else:
                # Show their own commission details when viewing as agent
                details = details.filter(position=request.user.profile.role)
            
            if not details.exists():
                messages.error(request, 'No commission details found.')
                return redirect('commission_history')

            # Calculate totals only for visible details
            total_gross = sum(detail.gross_commission for detail in details)
            total_tax = sum(detail.withholding_tax for detail in details)
            total_net = sum(detail.net_commission for detail in details)

            # Get all slips for the current user (either created or assigned)
            all_slips = CommissionSlip.objects.filter(
                Q(created_by=request.user) | Q(sales_agent_name=request.user.get_full_name())
            ).order_by('-id')

            return render(request, 'commission.html', {
                'slip': slip,
                'details': details,
                'total_gross': total_gross,
                'total_tax': total_tax,
                'total_net': total_net,
                'all_slips': all_slips,
                'viewing_as_creator': is_creator and not is_agent
            })
        else:
            messages.error(request, 'You do not have permission to view commission slips.')
            return redirect('commission_history')
    
    return redirect('commission_history')



def commission2(request, slip_id):
    if not request.user.is_authenticated:
        return redirect('signin')

    slip = get_object_or_404(CommissionSlip, id=slip_id)
    
    # Check if user has permission to view this commission2 slip
    can_view = (
        request.user.is_superuser or
        request.user.is_staff or  # Add staff permission
        slip.created_by == request.user or
        slip.sales_agent_name == request.user.get_full_name()
    )

    if not can_view:
        messages.error(request, 'You do not have permission to view this page.')
        return redirect('home')

    # Filter details based on user role and permissions
    if request.user.is_superuser:
        # Superusers can see all details
        details = CommissionDetail.objects.filter(slip=slip)
    elif request.user.is_staff and hasattr(request.user, 'profile') and request.user.profile.role == 'Sales Manager':
        # Sales Managers can see sales-related positions only (hide management positions)
        # Use exclude approach to be more explicit about hiding management positions
        management_positions = ['Operations Manager', 'Operation Manager', 'Co-Founder', 'Cofounder', 'Co Founder', 'Founder', 'Funds']
        details = CommissionDetail.objects.filter(slip=slip).exclude(position__in=management_positions)
    elif request.user.is_staff:
        # Other staff can see all details
        details = CommissionDetail.objects.filter(slip=slip)
    else:
        # Only show the detail for the user's role and name
        details = CommissionDetail.objects.filter(
            slip=slip,
            position=request.user.profile.role,
            agent_name=request.user.get_full_name()
        )

    # Get slips based on user role
    if request.user.is_superuser:
        # Superusers can see all slips
        all_slips = CommissionSlip.objects.all().order_by('-id')
    elif request.user.is_staff:
        # Staff can see all slips they created or where they are the agent
        all_slips = CommissionSlip.objects.filter(
            Q(created_by=request.user) | 
            Q(sales_agent_name=request.user.get_full_name())
        ).order_by('-id')
    else:
        # Others can only see their own slips
        all_slips = CommissionSlip.objects.filter(
            sales_agent_name=request.user.get_full_name()
        ).order_by('-id')

    # Calculate totals based on filtered details
    total_gross = sum(detail.gross_commission for detail in details)
    total_tax = sum(detail.withholding_tax for detail in details)
    total_net = sum(detail.net_commission for detail in details)

    return render(request, "commission2.html", {
        "slip": slip,
        "details": details,
        "total_gross": total_gross,
        "total_tax": total_tax,
        "total_net": total_net,
        "all_slips": all_slips,
    })

def commission_slip_view(request, slip_id):
    # Fetch the commission slip by ID
    slip = get_object_or_404(CommissionSlip, id=slip_id)
    return render(request, 'commission2.html', {'slip': slip})

@login_required
@require_http_methods(["POST"])
def save_signature(request):
    logger.info("save_signature view called.")
    try:
        data = json.loads(request.body)
        logger.info(f"Request body: {data}")
        slip_id = data.get('slip_id')
        slip_type = data.get('slip_type', 'commission')  # Default to 'commission'
        signature_data = data.get('signature')

        if not slip_id or not signature_data:
            logger.error("Missing slip_id or signature data.")
            return JsonResponse({'status': 'error', 'message': 'Missing slip_id or signature data.'}, status=400)

        logger.info(f"Attempting to save signature for slip_id: {slip_id} of type: {slip_type}")
        
        if slip_type == 'commission3':
            slip = get_object_or_404(CommissionSlip3, id=slip_id)
        else:
            slip = get_object_or_404(CommissionSlip, id=slip_id)

        # Decode the base64 image
        format, imgstr = signature_data.split(';base64,')
        ext = format.split('/')[-1]
        signature_file = ContentFile(base64.b64decode(imgstr), name=f'signature_{slip_id}.{ext}')

        slip.signature = signature_file
        slip.save()

        logger.info(f"Signature for {slip_type} slip_id {slip_id} saved successfully.")
        return JsonResponse({'status': 'success', 'message': 'Signature saved successfully.'})

    except Exception as e:
        logger.error(f"Error saving signature: {e}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required(login_url='signin')
def create_commission_slip2(request):
    if not request.user.is_staff and not request.user.is_superuser:
        messages.error(request, "You don't have permission to create commission slips.")
        return redirect('commission_history')

    if request.method == 'POST':
        post_data = request.POST.copy()
        agent_id = post_data.get('agent_select')
        if agent_id:
            try:
                agent = User.objects.get(id=agent_id)
                post_data['sales_agent_name'] = agent.get_full_name()
            except User.DoesNotExist:
                pass  # Handle case where agent_id is invalid or not found

        slip_form = CommissionSlipForm(post_data)
        if slip_form.is_valid():
            particulars = slip_form.cleaned_data.get('particulars')
            slip = slip_form.save(commit=False)
            slip.created_by = request.user
            slip.is_full_breakdown = True
            slip.source = 'full_breakdown'  # Set the source
            slip.position = request.POST.get('position', '')
            slip.save()

            positions = request.POST.getlist('position')
            is_primary_list = request.POST.getlist('is_primary')
            manager_rate = request.POST.get('manager_commission_rate', '0')
            other_rates = request.POST.getlist('commission_rate')
            partial_percentage_list = request.POST.getlist('partial_percentage')
            partial_percentage = Decimal(partial_percentage_list[0] if partial_percentage_list else '0')

            net_cash_advance = slip.cash_advance - (slip.cash_advance * Decimal('0.10'))
            adjusted_total = Decimal(slip.total_selling_price) - Decimal(net_cash_advance)

            other_rates_iterator = iter(other_rates)
            for i in range(len(positions)):
                position = positions[i]
                is_primary = is_primary_list[i] == 'true' if i < len(is_primary_list) else False

                if is_primary:
                    rate_str = manager_rate
                else:
                    try:
                        rate_str = next(other_rates_iterator)
                    except StopIteration:
                        rate_str = '0'

                rate = Decimal(rate_str or '0')

                if rate > 0:
                    if is_primary:
                        tax_rate = slip.withholding_tax_rate
                    elif position == 'Operation Manager':
                        tax_rate = slip.operation_manager_tax_rate
                    elif position == 'Co-Founder':
                        tax_rate = slip.co_founder_tax_rate
                    elif position == 'Founder':
                        tax_rate = slip.founder_tax_rate
                    elif position == 'Funds':
                        tax_rate = Decimal('0')
                    else:
                        tax_rate = Decimal('0')

                    base_commission = adjusted_total * (rate / 100)
                    gross_commission = base_commission * (partial_percentage / 100)
                    withholding_tax = gross_commission * (tax_rate / 100)
                    net_commission = gross_commission - withholding_tax

                    CommissionDetail.objects.create(
                        slip=slip,
                        position=position,
                        particulars=particulars,
                        commission_rate=rate,
                        gross_commission=gross_commission.quantize(Decimal('0.01')),
                        withholding_tax=withholding_tax.quantize(Decimal('0.01')),
                        net_commission=net_commission.quantize(Decimal('0.01')),
                        partial_percentage=partial_percentage,
                        withholding_tax_rate=tax_rate
                    )

            messages.success(request, "Commission slip created successfully!")
            return redirect('commission_history')
    else:
        slip_form = CommissionSlipForm()

    # Get all properties for the dropdown
    properties = Property.objects.all().order_by('name')
    
    context = {
        'slip_form': slip_form,
        'active_users': User.objects.filter(profile__is_approved=True),
        'properties': properties
    }
    return render(request, 'create_commission_slip2.html', context)




def commission_view2(request, slip_id):
    if not request.user.is_authenticated:
        return redirect('signin')

    # Check if user has permission to view commission slip 2
    if not (request.user.is_superuser or request.user.profile.role in ['Sales Manager', 'Sales Supervisor']):
        messages.error(request, 'You do not have permission to view this page.')
        return redirect('home')

    slip = get_object_or_404(CommissionSlip, id=slip_id)
    details = CommissionDetail.objects.filter(slip=slip)

    # Get slips based on user role
    if request.user.is_superuser:
        # Superusers can see all slips
        all_slips = CommissionSlip.objects.all().order_by('-id')
    elif request.user.profile.role == 'Sales Manager':
        # Managers can see their team's slips
        all_slips = CommissionSlip.objects.filter(
            Q(created_by=request.user) | 
            Q(sales_agent_name=request.user.get_full_name())
        ).order_by('-id')
    else:
        # Supervisors can only see their own slips
        all_slips = CommissionSlip.objects.filter(
            sales_agent_name=request.user.get_full_name()
        ).order_by('-id')

    total_gross = sum(detail.gross_commission for detail in details)
    total_tax = sum(detail.withholding_tax for detail in details)
    total_net = sum(detail.net_commission for detail in details)

    return render(request, "commission2.html", {
        "slip": slip,
        "details": details,
        "total_gross": total_gross,
        "total_tax": total_tax,
        "total_net": total_net,
        "all_slips": all_slips,
    })

def edit_commission_slip(request, slip_id):
    slip = get_object_or_404(CommissionSlip, id=slip_id)

    if request.method == "POST":
        # Update Commission Slip fields
        slip.sales_agent_name = request.POST.get("sales_agent_name")
        slip.buyer_name = request.POST.get("buyer_name")
        slip.project_name = request.POST.get("project_name")
        slip.unit_id = request.POST.get("unit_id")
        slip.total_selling_price = float(request.POST.get("total_selling_price") or 0)
        slip.commission_rate = float(request.POST.get("commission_rate") or 0)
        slip.save()

        # Loop through each detail
        for detail in CommissionDetail.objects.filter(slip=slip):
            commission_rate_str = request.POST.get(f"commission_rate_{detail.id}")
            if commission_rate_str is not None:
                detail.commission_rate = float(commission_rate_str)

            particulars_val = request.POST.get(f"particulars_{detail.id}")
            if particulars_val is not None:
                detail.particulars = particulars_val

            is_incentive = detail.particulars == "INCENTIVES" and detail.position == "dynamic_position"

            if is_incentive:
                # Preserve incentive amount and compute from it
                incentive_amount = request.POST.get(f"incentive_amount_{detail.id}")
                if incentive_amount:
                    detail.incentive_amount = float(incentive_amount)
                else:
                    detail.incentive_amount = 0

                detail.gross_commission = detail.incentive_amount
            else:
                # Recompute for regular items
                detail.incentive_amount = 0
                detail.gross_commission = slip.total_selling_price * (detail.commission_rate / 100)

            # Always recalculate tax and net commission
            detail.withholding_tax = detail.gross_commission * 0.10
            detail.net_commission = detail.gross_commission - detail.withholding_tax

            detail.save()

        return redirect('commission2', slip_id=slip.id)

    # For GET request, load the form
    details = CommissionDetail.objects.filter(slip=slip)
    total_gross = sum(d.gross_commission for d in details)
    total_tax = sum(d.withholding_tax for d in details)
    total_net = sum(d.net_commission for d in details)
    all_slips = CommissionSlip.objects.order_by('-id')

    return render(request, "commission2.html", {
        "slip": slip,
        "details": details,
        "total_gross": total_gross,
        "total_tax": total_tax,
        "total_net": total_net,
        "all_slips": all_slips,
        "edit_mode": True,
    })


@login_required(login_url='signin')
def delete_commission_slip(request, slip_id):
    # Try to get the commission slip from all possible models
    slip = None
    for model in [CommissionSlip, CommissionSlip3]:
        try:
            slip = model.objects.get(id=slip_id)
            break
        except model.DoesNotExist:
            continue
    
    if not slip:
        messages.error(request, 'Commission slip not found.')
        return redirect('commission_history')
    
    # Check if user has permission to delete the slip
    if not (request.user.is_superuser or request.user.is_staff):
        messages.error(request, 'You do not have permission to delete commission slips.')
        return redirect('commission_history')
    
    if request.method == "POST":
        try:
            # Delete associated commission details first
            if hasattr(slip, 'details'):
                slip.details.all().delete()
            
            # Delete associated commission records
            Commission.objects.filter(
                project_name=slip.project_name,
                buyer=slip.buyer_name
            ).delete()
            
            # Delete the commission slip
            slip.delete()
            messages.success(request, 'Commission slip deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting commission slip: {str(e)}')
        
    return redirect('commission_history')







@login_required(login_url='signin')
def tranches_view(request):
    # Check if user has permission
    if not request.user.is_staff and not request.user.is_superuser:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('home')

    # Get all approved users
    approved_users = User.objects.filter(
        profile__is_approved=True,
        profile__role__in=['Sales Agent', 'Sales Supervisor', 'Sales Manager']
    ).select_related('profile')
    
    # Get all properties for the dropdown
    properties = Property.objects.all().select_related('developer')
    
    # Initialize variables for Excel processing
    excel_results = None
    excel_form = ExcelUploadForm()

    if request.method == 'POST':
        # Check if this is an Excel upload request
        if 'excel_file' in request.FILES:
            logger.info(f"Excel file upload detected. Files: {list(request.FILES.keys())}")
            excel_form = ExcelUploadForm(request.POST, request.FILES)
            
            if excel_form.is_valid():
                try:
                    import pandas as pd
                    import io
                    
                    excel_file = excel_form.cleaned_data['excel_file']
                    logger.info(f"Processing Excel file: {excel_file.name}, Size: {excel_file.size} bytes")
                    
                    # Read Excel file using pandas with openpyxl engine
                    df = pd.read_excel(
                        io.BytesIO(excel_file.read()),
                        engine='openpyxl'
                    )
                    
                    logger.info(f"Excel file loaded successfully. Shape: {df.shape}, Columns: {list(df.columns)}")
                    
                    # Validate required columns
                    required_columns = [
                        'agent_name', 'buyer_name', 'project_name', 'unit_id',
                        'total_contract_price', 'commission_rate'
                    ]
                    
                    missing_columns = [col for col in required_columns if col not in df.columns]
                    if missing_columns:
                        error_message = f"Missing required columns: {', '.join(missing_columns)}"
                        messages.error(request, error_message)
                        logger.error(f"Missing columns: {missing_columns}")
                    else:
                        # Process each row and perform tranche calculations
                        processed_results = []
                        
                        for index, row in df.iterrows():
                            try:
                                # Extract data from row
                                agent_name = str(row['agent_name']).strip()
                                buyer_name = str(row['buyer_name']).strip()
                                project_name = str(row['project_name']).strip()
                                unit_id = str(row['unit_id']).strip()
                                total_contract_price = Decimal(str(row['total_contract_price']))
                                commission_rate = Decimal(str(row['commission_rate']))
                                
                                # Optional fields with defaults
                                vat_rate = Decimal(str(row.get('vat_rate', 12)))
                                withholding_tax_rate = Decimal(str(row.get('withholding_tax_rate', 10)))
                                process_fee_percentage = Decimal(str(row.get('process_fee_percentage', 0)))
                                option1_percentage = Decimal(str(row.get('option1_percentage', 50)))
                                option2_percentage = Decimal(str(row.get('option2_percentage', 50)))
                                other_deductions = Decimal(str(row.get('other_deductions', 0)))
                                
                                # Perform tranche calculations
                                calculations = perform_excel_tranche_calculations(
                                    total_contract_price=total_contract_price,
                                    commission_rate=commission_rate,
                                    vat_rate=vat_rate,
                                    withholding_tax_rate=withholding_tax_rate,
                                    process_fee_percentage=process_fee_percentage,
                                    option1_percentage=option1_percentage,
                                    option2_percentage=option2_percentage,
                                    other_deductions=other_deductions
                                )
                                
                                # Add row data to calculations
                                calculations.update({
                                    'row_number': index + 1,
                                    'agent_name': agent_name,
                                    'buyer_name': buyer_name,
                                    'project_name': project_name,
                                    'unit_id': unit_id,
                                    'total_contract_price': float(total_contract_price),
                                    'commission_rate': float(commission_rate),
                                })
                                
                                processed_results.append(calculations)
                                logger.info(f"Successfully processed row {index + 1}")
                                
                            except Exception as row_error:
                                logger.error(f"Error processing row {index + 1}: {str(row_error)}")
                                processed_results.append({
                                    'row_number': index + 1,
                                    'error': f"Error processing row {index + 1}: {str(row_error)}",
                                    'agent_name': row.get('agent_name', 'N/A'),
                                    'buyer_name': row.get('buyer_name', 'N/A'),
                                    'project_name': row.get('project_name', 'N/A'),
                                })
                        
                        excel_results = {
                            'total_rows': len(df),
                            'processed_rows': len(processed_results),
                            'results': processed_results,
                            'filename': excel_file.name
                        }
                        
                        messages.success(request, f'Successfully processed {len(processed_results)} rows from {excel_file.name}')
                        logger.info(f"Excel processing completed successfully. Processed {len(processed_results)} rows")
                        
                except Exception as e:
                    error_message = f"Error processing Excel file: {str(e)}"
                    messages.error(request, error_message)
                    logger.error(f"Excel processing error: {str(e)}")
            else:
                messages.error(request, "Please correct the form errors below.")
                logger.error(f"Excel form validation errors: {excel_form.errors}")
        else:
            # Handle regular form submission
            form = CommissionForm(request.POST)
            if form.is_valid():
                try:
                    # Create TrancheRecord
                    tranche_record = TrancheRecord.objects.create(
                        project_name=form.cleaned_data['project_name'],
                        agent_name=form.cleaned_data['agent_name'].get_full_name(),
                        phase=form.cleaned_data['phase'],
                        unit_id=form.cleaned_data['unit_id'],
                        buyer_name=form.cleaned_data['buyer_name'],
                        reservation_date=form.cleaned_data['reservation_date'],
                        total_contract_price=form.cleaned_data['total_contract_price'],
                        commission_rate=form.cleaned_data['commission_rate'],
                        process_fee_percentage=form.cleaned_data.get('process_fee_percentage', 0),
                        withholding_tax_rate=form.cleaned_data['withholding_tax_rate'],
                        option1_percentage=form.cleaned_data['option1_percentage'],
                        option2_percentage=form.cleaned_data['option2_percentage'],
                        option1_tax_rate=form.cleaned_data['option1_tax_rate'],
                        option2_tax_rate=form.cleaned_data['option2_tax_rate'],
                        tranche_option=form.cleaned_data['tranche_option'],
                        number_months=form.cleaned_data['number_months'],
                        deduction_type=form.cleaned_data.get('deduction_type'),
                        other_deductions=form.cleaned_data.get('other_deductions', 0),
                        # Store the raw Net of VAT divisor input from the form
                        net_of_vat_amount=form.cleaned_data.get('net_of_vat_amount', 0),
                        vat_rate=form.cleaned_data['vat_rate'],
                        deduction_tax_rate=form.cleaned_data.get('deduction_tax_rate', 10),
                        created_by=request.user
                    )
                    print("Created TrancheRecord:", tranche_record.id)

                    # Calculate base values using two paths based on Net of VAT input
                    net_of_vat_divisor = form.cleaned_data.get('net_of_vat_amount', 0)
                    total_contract_price = form.cleaned_data['total_contract_price']
                    
                    if net_of_vat_divisor and net_of_vat_divisor > 0:
                        # Path 1: Use Net of VAT divisor calculation
                        net_of_vat_base = total_contract_price / net_of_vat_divisor
                        less_process_fee = (net_of_vat_base * form.cleaned_data.get('process_fee_percentage', 0)) / Decimal(100)
                        total_selling_price = net_of_vat_base - less_process_fee
                        gross_commission = total_selling_price * (form.cleaned_data['commission_rate'] / Decimal(100))
                    else:
                        # Path 2: Use Total Contract Price directly
                        net_of_vat_base = total_contract_price
                        less_process_fee = total_contract_price * (form.cleaned_data.get('process_fee_percentage', 0) / Decimal(100))
                        total_selling_price = total_contract_price - less_process_fee
                        gross_commission = total_selling_price * (form.cleaned_data['commission_rate'] / Decimal(100))

                    # Common calculations for both paths
                    tax_rate = form.cleaned_data['withholding_tax_rate'] / Decimal(100)
                    vat_rate_decimal = form.cleaned_data.get('vat_rate', Decimal(12)) / Decimal(100)
                    
                    # Calculate VAT and Net of VAT from gross commission
                    vat_amount = gross_commission * vat_rate_decimal
                    net_of_vat = gross_commission - vat_amount
                    
                    # Calculate withholding tax and final net commission
                    tax = net_of_vat * tax_rate
                    net_commission = net_of_vat - tax

                    print("Base calculations completed")

                    # Calculate tax rates for different components
                    option1_tax_rate = form.cleaned_data['option1_tax_rate'] / Decimal(100)
                    option2_tax_rate = form.cleaned_data['option2_tax_rate'] / Decimal(100)
                    deduction_tax_rate = form.cleaned_data.get('deduction_tax_rate', Decimal(10)) / Decimal(100)

                    print("Tax rates calculated:", {
                        "option1_tax_rate": option1_tax_rate,
                        "option2_tax_rate": option2_tax_rate,
                        "deduction_tax_rate": deduction_tax_rate
                    })

                    # Calculate deductions
                    deduction_amount = form.cleaned_data.get('other_deductions', Decimal(0))
                    deduction_tax = deduction_amount * deduction_tax_rate
                    deduction_net = deduction_amount - deduction_tax

                    print("Deductions calculated:", {
                        "amount": deduction_amount,
                        "tax": deduction_tax,
                        "net": deduction_net
                    })

                    # Calculate commission splits
                    total_commission = net_commission
                    option1_value_before_deduction = total_commission * (form.cleaned_data['option1_percentage'] / Decimal(100))
                    option2_value = total_commission * (form.cleaned_data['option2_percentage'] / Decimal(100))

                    # Apply deductions to option1_value (DP period)
                    option1_value = option1_value_before_deduction - deduction_net
                    option1_monthly = option1_value / Decimal(form.cleaned_data['number_months'])

                    print("Commission splits calculated:", {
                        "option1_before_deduction": option1_value_before_deduction,
                        "option1_after_deduction": option1_value,
                        "option2_value": option2_value,
                        "monthly_value": option1_monthly
                    })

                    # Create payment schedule
                    intervals = []
                    current_date = form.cleaned_data['reservation_date']
                    for i in range(form.cleaned_data['number_months']):
                        if form.cleaned_data['tranche_option'] == "bi_monthly":
                            current_date += timedelta(days=30)
                        elif form.cleaned_data['tranche_option'] == "quarterly":
                            current_date += timedelta(days=90)
                        elif form.cleaned_data['tranche_option'] == "bi_6_months":
                            current_date += timedelta(days=180)
                        elif form.cleaned_data['tranche_option'] == "bi_9_months":
                            current_date += timedelta(days=270)
                        else:
                            current_date += timedelta(days=30)
                        intervals.append(current_date)

                    print(f"Created {len(intervals)} payment intervals")

                    # Create DP tranches
                    dp_tranches = []
                    total_net = Decimal('0')
                    total_dp_tax = Decimal('0')

                    # Calculate totals first
                    for i, date in enumerate(intervals, start=1):
                        net = option1_monthly
                        tax_amount = net * option1_tax_rate
                        total_net += net
                        total_dp_tax += tax_amount

                    total_expected_commission = total_net - total_dp_tax
                    remaining_balance = total_expected_commission

                    print("DP period totals calculated:", {
                        "total_net": total_net,
                        "total_tax": total_dp_tax,
                        "expected_commission": total_expected_commission
                    })

                    # Create individual tranches
                    for i, date in enumerate(intervals, start=1):
                        net = option1_monthly
                        tax_amount = net * option1_tax_rate
                        expected_commission = net - tax_amount
                        commission_received = Decimal(request.POST.get(f"commission_received_{i}", 0) or 0)
                        date_received = request.POST.get(f"date_received_{i}")

                        remaining_balance = remaining_balance - commission_received

                        tranche = TranchePayment.objects.create(
                            tranche_record=tranche_record,
                            tranche_number=i,
                            expected_date=date,
                            expected_amount=expected_commission,
                            received_amount=commission_received,
                            date_received=date_received if date_received else None,
                            is_lto=False,
                            initial_balance=total_expected_commission,
                            status="Received" if commission_received >= expected_commission else
                                   "Partial" if commission_received > 0 else "Pending"
                        )
                        dp_tranches.append({
                            'tranche': tranche,
                            'tax_amount': tax_amount,
                            'net_amount': net,
                            'balance': remaining_balance,
                            'initial_balance': total_expected_commission,
                            'expected_commission': expected_commission
                        })

                    print(f"Created {len(dp_tranches)} DP tranches")

                    # Calculate LTO values
                    total_commission_received = sum(t['tranche'].received_amount for t in dp_tranches)
                    total_commission1 = total_expected_commission

                    lto_deduction_value = option2_value
                    lto_deduction_tax = lto_deduction_value * option2_tax_rate
                    lto_deduction_net = lto_deduction_value - lto_deduction_tax
                    lto_expected_commission = lto_deduction_net - lto_deduction_tax

                    print("LTO calculations:", {
                        "deduction_value": lto_deduction_value,
                        "tax": lto_deduction_tax,
                        "net": lto_deduction_net,
                        "expected_commission": lto_expected_commission
                    })

                    # Create LTO tranche
                    schedule2_gap_months = int(request.POST.get("schedule2_gap_months", 1))
                    schedule2_start_date = intervals[-1] + timedelta(days=30 * schedule2_gap_months)

                    commission_received2 = Decimal(request.POST.get("commission_received2_1", 0) or 0)
                    date_received2 = request.POST.get("date_received2_1")

                    lto_current_balance = lto_expected_commission - commission_received2

                    lto_tranche = TranchePayment.objects.create(
                        tranche_record=tranche_record,
                        tranche_number=1,
                        expected_date=schedule2_start_date,
                        expected_amount=lto_expected_commission,
                        received_amount=commission_received2,
                        date_received=date_received2 if date_received2 else None,
                        is_lto=True,
                        initial_balance=lto_expected_commission,
                        status="Received" if commission_received2 >= lto_expected_commission else
                               "Partial" if commission_received2 > 0 else "Pending"
                    )

                    print("Created LTO tranche")

                    lto_tranches = [{
                        'tranche': lto_tranche,
                        'tax_amount': lto_deduction_tax,
                        'net_amount': lto_deduction_net,
                        'expected_commission': lto_expected_commission,
                        'balance': lto_current_balance,
                        'initial_balance': lto_expected_commission
                    }]

                    # Calculate final totals
                    total_commission2 = sum(t['tranche'].expected_amount for t in lto_tranches)
                    total_commission_received2 = sum(t['tranche'].received_amount for t in lto_tranches)
                    total_balance2 = total_commission2 - total_commission_received2
                    percentage_received2 = (total_commission_received2 / total_commission2 * 100) if total_commission2 > 0 else 0
                    percentage_remaining2 = 100 - percentage_received2

                    total_dp_tax = sum(t['tax_amount'] for t in dp_tranches)

                    # Calculate total tax for LTO tranche so it can be included in the context
                    total_lto_tax = lto_deduction_tax

                    print("Final calculations completed")

                    # Prepare context with all calculated values
                    context = {
                        "form": form,
                        "approved_users": approved_users,
                        "project_name": form.cleaned_data['project_name'],
                        "agent_name": form.cleaned_data['agent_name'].get_full_name(),
                        "phase": form.cleaned_data['phase'],
                        "unit_id": form.cleaned_data['unit_id'],
                        "buyer_name": form.cleaned_data['buyer_name'],
                        "reservation_date": form.cleaned_data['reservation_date'],
                        "total_contract_price": form.cleaned_data['total_contract_price'],
                        "less_process_fee": less_process_fee,
                        "total_selling_price": total_selling_price,
                        "commission_rate": form.cleaned_data['commission_rate'],
                        "gross_commission": gross_commission,
                        "vat_rate": tranche_record.vat_rate,
                        "net_of_vat": net_of_vat,
                        "vat_amount": vat_amount,
                        "tax": tax_rate * 100,
                        "tax_rate": tax,
                        "net_commission": net_commission,
                        "dp_tranches": dp_tranches,
                        "lto_tranches": lto_tranches,
                        "option1_value": option1_value,
                        "option1_value_before_deduction": option1_value_before_deduction,
                        "option2_value": option2_value,
                        "option1_percentage": form.cleaned_data['option1_percentage'],
                        "option2_percentage": form.cleaned_data['option2_percentage'],
                        "option1_tax_rate": option1_tax_rate,
                        "option2_tax_rate": option2_tax_rate,
                        "tranche_option": form.cleaned_data['tranche_option'],
                        "number_months": form.cleaned_data['number_months'],
                        "process_fee_percentage": form.cleaned_data.get('process_fee_percentage', Decimal(0)),
                        "withholding_tax_rate": form.cleaned_data['withholding_tax_rate'],
                        "option1_monthly": option1_monthly,
                        "total_commission1": total_commission1,
                        "total_commission_received": total_commission_received,
                        "total_balance": total_commission1 - total_commission_received,
                        "percentage_received": (total_commission_received / total_commission1 * 100) if total_commission1 > 0 else 0,
                        "percentage_remaining": 100 - (total_commission_received / total_commission1 * 100) if total_commission1 > 0 else 0,
                        "other_deductions": form.cleaned_data.get('other_deductions', Decimal(0)),
                        "deduction_type": form.cleaned_data.get('deduction_type'),
                        "deduction_tax": deduction_tax,
                        "deduction_net": deduction_net,
                        "deductions": option1_value,
                        "deduction_tax_rate": deduction_tax_rate * 100,
                        "schedule2_start_date": schedule2_start_date,
                        "schedule2_gap_months": schedule2_gap_months,
                        "total_commission2": total_commission2,
                        "total_commission_received2": total_commission_received2,
                        "total_balance2": total_balance2,
                        "percentage_received2": percentage_received2,
                        "percentage_remaining2": percentage_remaining2,
                        "total_dp_tax": total_dp_tax,
                        "total_lto_tax": total_lto_tax,
                        "lto_deduction_value": lto_deduction_value,
                        "lto_deduction_tax": lto_deduction_tax,
                        "lto_deduction_net": lto_deduction_net,
                    }

                    messages.success(request, 'Tranche record created successfully!')
                    # Redirect to the tranche details page so the user can immediately review the generated report
                    return redirect(reverse('view_tranche', args=[tranche_record.id]))

                except Exception as e:
                    print("Error creating tranche record:", str(e))
                    messages.error(request, f"Error creating tranche record: {str(e)}")
                    return render(request, "tranches.html", {"form": form, "approved_users": approved_users, "properties": properties})

    form = CommissionForm()
    context = {
        "form": form,
        "approved_users": approved_users,
        "properties": properties,
        "excel_form": excel_form,
        "excel_results": excel_results,
        "option1_tax_rate": Decimal("0.10"),
        "option2_tax_rate": Decimal("0.10"),
        "option1_value": Decimal("0"),
        "option2_value": Decimal("0")
    }
    return render(request, "tranches.html", context)

@login_required(login_url='signin')
def add_sale(request):
    if request.method == 'POST':
        try:
            property_name = request.POST.get('property')
            developer = request.POST.get('developer')
            amount = request.POST.get('amount')
            status = request.POST.get('status')
            date = request.POST.get('date')

            # Validate that property and developer exist in our database
            if not Property.objects.filter(name=property_name).exists():
                messages.error(request, 'Selected property does not exist.')
                return redirect('profile')
                
            if not Developer.objects.filter(name=developer).exists():
                messages.error(request, 'Selected developer does not exist.')
                return redirect('profile')

            if all([property_name, developer, amount, status, date]):
                # Create the sale
                sale = Sale.objects.create(
                    user=request.user,
                    property_name=property_name,
                    developer=developer,
                    amount=amount,
                    status=status,
                    date=date
                )
                messages.success(request, 'Sale added successfully!')
            else:
                messages.error(request, 'Please fill all required fields.')
        except Exception as e:
            messages.error(request, f'Error adding sale: {str(e)}')
    
    return redirect('profile')

@login_required
def get_sale(request, sale_id):
    if request.user.is_superuser:
        sale = get_object_or_404(Sale, id=sale_id)
    else:
        sale = get_object_or_404(Sale, id=sale_id, user=request.user)
    return JsonResponse({
        'date': sale.date.strftime('%Y-%m-%d') if sale.date else '',
        'property_name': sale.property_name,
        'developer': sale.developer,
        'amount': str(sale.amount),
        'status': sale.status
    })

@login_required
def edit_sale(request, sale_id):
    if request.user.is_superuser:
        sale = get_object_or_404(Sale, id=sale_id)
    else:
        sale = get_object_or_404(Sale, id=sale_id, user=request.user)
    if request.method == 'POST':
        try:
            property_name = request.POST['property']
            developer = request.POST['developer']
            
            # Validate that property and developer exist
            if not Property.objects.filter(name=property_name).exists():
                messages.error(request, 'Selected property does not exist.')
                return redirect('profile')
                
            if not Developer.objects.filter(name=developer).exists():
                messages.error(request, 'Selected developer does not exist.')
                return redirect('profile')
            
            # Convert the date string to a datetime object
            sale_date = datetime.strptime(request.POST['date'], '%Y-%m-%d').date()
            
            # Update sale
            sale.date = sale_date
            sale.property_name = property_name
            sale.developer = developer
            sale.amount = request.POST['amount']
            sale.status = request.POST['status']
            sale.save()
            
            messages.success(request, 'Sale updated successfully!')
        except (ValueError, KeyError) as e:
            messages.error(request, f'Error updating sale: {str(e)}')
    return redirect('profile')

@login_required
def delete_sale(request, sale_id):
    if request.user.is_superuser: 
        sale = get_object_or_404(Sale, id=sale_id)
    else:
        sale = get_object_or_404(Sale, id=sale_id, user=request.user)
    sale.delete()
    return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)


@login_required
def view_receivable_voucher(request, release_number):
    """Display receivable data in commission voucher format using tranche data"""
    if not request.user.is_authenticated:
        return redirect('signin')
    
    # Get the commission entry by release number
    try:
        commission_entry = Commission.objects.get(release_number=release_number)
    except Commission.DoesNotExist:
        messages.error(request, 'Receivable not found.')
        return redirect('receivables')
    
    # Check permissions - users can only view their own receivables unless superuser
    if not request.user.is_superuser and commission_entry.agent != request.user:
        messages.error(request, 'You do not have permission to view this receivable.')
        return redirect('receivables')
    
    # Get tranche information - this is now the primary data source
    tranche_id = None
    if 'DP-' in release_number:
        tranche_id = release_number.split('-')[1]
    elif 'LTO-' in release_number:
        tranche_id = release_number.split('-')[1]
    
    tranche_record = None
    if tranche_id:
        try:
            tranche_record = TrancheRecord.objects.get(id=tranche_id)
        except TrancheRecord.DoesNotExist:
            pass
    
    # Initialize all context variables to prevent UnboundLocalError
    gross_commission_value = Decimal('0.00')
    vat_amount = Decimal('0.00')
    withholding_tax_value = Decimal('0.00')
    net_commission_value = Decimal('0.00')
    total_deductions = Decimal('0.00')
    net_receivable = Decimal('0.00')
    tranche_payments = []
    total_selling_price = Decimal('0.00')

    # If we have tranche data, use it for calculations (EXACT same logic as view_tranche)
    if tranche_record:
        # Calculate base values using the Net of VAT divisor input field (EXACT same as view_tranche)
        # If net_of_vat_amount is provided, use it as divisor; otherwise use Total Contract Price directly
        if tranche_record.net_of_vat_amount and tranche_record.net_of_vat_amount > 0:
            # Path 1: Use the manually entered Net of VAT divisor: TCP / Net of VAT divisor
            net_of_vat_base = (Decimal(str(tranche_record.total_contract_price)) / Decimal(str(tranche_record.net_of_vat_amount))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            less_process_fee = (net_of_vat_base * tranche_record.process_fee_percentage) / Decimal(100)
            total_selling_price = net_of_vat_base - less_process_fee
            gross_commission_value = total_selling_price * (tranche_record.commission_rate / Decimal(100))
        else:
            # Path 2: Use Total Contract Price directly when Net of VAT is 0 or empty
            net_of_vat_base = tranche_record.total_contract_price
            less_process_fee = tranche_record.total_contract_price * (tranche_record.process_fee_percentage / Decimal(100))
            total_selling_price = tranche_record.total_contract_price - less_process_fee
            gross_commission_value = tranche_record.total_contract_price * (tranche_record.commission_rate / Decimal(100))

        # Common calculations for both paths (EXACT same as view_tranche)
        tax_rate = tranche_record.withholding_tax_rate / Decimal(100)
        vat_rate_decimal = tranche_record.vat_rate / Decimal(100)
        
        # Calculate VAT and Net of VAT from gross commission
        vat_amount = gross_commission_value * vat_rate_decimal
        net_of_vat = gross_commission_value - vat_amount
        
        # Calculate withholding tax and final net commission
        tax = net_of_vat * tax_rate
        withholding_tax_value = tax
        net_of_withholding_tax = net_of_vat - withholding_tax_value
        net_commission_value = net_of_vat - tax
        
        # Get DP tranches and calculate values (same as view_tranche)
        dp_payments = tranche_record.payments.filter(is_lto=False).order_by('tranche_number')
        dp_tranches = []
        
        # Calculate option1 values (DP period)
        option1_value_before_deduction = net_commission_value * (tranche_record.option1_percentage / Decimal(100))
        option1_tax_rate = tranche_record.option1_tax_rate / Decimal(100)
        
        # Apply deductions
        deduction_tax_rate = tranche_record.deduction_tax_rate / Decimal(100)
        deduction_tax = tranche_record.other_deductions * deduction_tax_rate
        deduction_net = tranche_record.other_deductions - deduction_tax
        
        option1_value = option1_value_before_deduction - deduction_net
        option1_monthly = option1_value / Decimal(tranche_record.number_months)
        
        # Calculate totals for DP period
        total_expected_commission = Decimal('0')
        for payment in dp_payments:
            net = option1_monthly
            tax_amount = net * option1_tax_rate
            expected_commission = net - tax_amount
            total_expected_commission += expected_commission
            
            dp_tranches.append({
                'tranche': payment,
                'tax_amount': tax_amount,
                'net_amount': net,
                'expected_commission': expected_commission,
                'balance': expected_commission - payment.received_amount,
                'initial_balance': payment.initial_balance
            })
        
        # Calculate LTO values
        option2_value = net_commission_value * (tranche_record.option2_percentage / Decimal(100))
        option2_tax_rate = tranche_record.option2_tax_rate / Decimal(100)
        lto_deduction_value = option2_value
        lto_deduction_tax = lto_deduction_value * option2_tax_rate
        lto_deduction_net = lto_deduction_value - lto_deduction_tax
        lto_expected_commission = lto_deduction_net.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        
        # Get LTO tranche
        lto_payment = tranche_record.payments.filter(is_lto=True).first()
        lto_tranches = []
        if lto_payment:
            lto_tranches.append({
                'tranche': lto_payment,
                'tax_amount': lto_deduction_tax,
                'net_amount': lto_deduction_net,
                'expected_commission': lto_expected_commission,
                'balance': lto_expected_commission - lto_payment.received_amount,
                'initial_balance': lto_payment.initial_balance
            })
        
        commission_rate = tranche_record.commission_rate
        unit_id = getattr(tranche_record, 'unit_id', f"Unit-{tranche_record.id}")
        tcp = tranche_record.total_contract_price
        lot_area = getattr(tranche_record, 'lot_area', 'N/A')
        floor_area = getattr(tranche_record, 'floor_area', 'N/A')
        
        # Determine which tranche data to use based on release number
        if 'DP-' in release_number and dp_tranches:
            # Use DP tranche data - use the exact values from tranche schedule calculations
            tranche_data_source = dp_tranches[0]  # Use first DP tranche
            gross_commission_value = tranche_data_source['net_amount']  # net_amount for DP (matches view_tranche display)
            withholding_tax_value = tranche_data_source['tax_amount']   # tax_amount for DP (matches view_tranche display)
            net_commission_value = tranche_data_source['expected_commission']  # expected_commission for DP (matches view_tranche display)
        elif 'LTO-' in release_number and lto_tranches:
            # Use LTO tranche data - use the exact values from tranche schedule calculations
            tranche_data_source = lto_tranches[0]
            gross_commission_value = lto_deduction_value  # lto_deduction_value for LTO (matches view_tranche display)
            withholding_tax_value = lto_deduction_tax     # lto_deduction_tax for LTO (matches view_tranche display)
            net_commission_value = lto_deduction_net      # lto_deduction_net for LTO (matches view_tranche display)
        else:
            # Fallback to calculated values (should not happen with proper tranche data)
            gross_commission_value = net_commission_value
            withholding_tax_value = withholding_tax_value
            net_commission_value = net_commission_value
            
    else:
        # Fallback to basic commission data if no tranche found
        total_selling_price = Decimal('0')
        net_amount = commission_entry.commission_amount
        tax_amount = Decimal('0')
        expected_commission = commission_entry.commission_amount
        commission_rate = 0
        unit_id = 'N/A'
        tcp = 0
        lot_area = 'N/A'
        floor_area = 'N/A'
    
    # Create a mock commission slip object for the template
    class MockCommissionSlip:
        def __init__(self, commission_entry, tranche_data):
            self.id = f"RCV-{commission_entry.id}"
            self.date = commission_entry.date_released.strftime('%B %d, %Y')
            self.sales_agent_name = commission_entry.agent.get_full_name() or commission_entry.agent.username
            self.buyer_name = commission_entry.buyer
            self.project_name = commission_entry.project_name
            self.developer = commission_entry.developer
            self.release_number = commission_entry.release_number
            self.payment_type = 'Loan Take Out' if 'LTO' in commission_entry.release_number else 'Down Payment'
            
            # Use tranche-based financial data
            self.unit_id = tranche_data['unit_id']
            self.total_selling_price = tranche_data['total_selling_price']
            self.cash_advance = Decimal('0')  # Receivables don't have cash advance
            self.incentive_amount = 0
            
            # Additional tranche-specific fields
            self.lot_area = tranche_data['lot_area']
            self.floor_area = tranche_data['floor_area']
            self.tcp = tranche_data['tcp']
    
    # Create mock commission details using tranche payment data
    class MockCommissionDetail:
        def __init__(self, commission_entry, tranche_data):
            self.position = 'Sales Agent'
            self.particulars = 'COMMISSION'
            self.commission_rate = tranche_data['commission_rate']
            self.gross_commission = tranche_data['gross_commission_value']  # Correct gross commission value
            self.withholding_tax = tranche_data['withholding_tax_value']   # Correct withholding tax value
            self.net_commission = tranche_data['net_commission_value']     # Correct net commission value
    
    # Package tranche data for mock objects
    tranche_data = {
        'unit_id': unit_id,
        'total_selling_price': total_selling_price,
        'tcp': tcp,
        'lot_area': lot_area,
        'floor_area': floor_area,
        'commission_rate': commission_rate,
        'gross_commission_value': gross_commission_value,    # Correct gross commission based on tranche type
        'withholding_tax_value': withholding_tax_value,     # Correct withholding tax based on tranche type
        'net_commission_value': net_commission_value        # Correct net commission based on tranche type
    }
    
    mock_slip = MockCommissionSlip(commission_entry, tranche_data)
    mock_details = [MockCommissionDetail(commission_entry, tranche_data)]
    
    context = {
        'slip': mock_slip,
        'details': mock_details,
        'is_receivable_view': True,  # Flag to indicate this is a receivable view
        'commission_entry': commission_entry,
        'tranche_record': tranche_record,
        'dp_tranches': dp_tranches if tranche_record else [],     # Pass DP tranches to template
        'lto_tranches': lto_tranches if tranche_record else [],   # Pass LTO tranches to template
        'lto_deduction_value': lto_deduction_value if tranche_record else 0,
        'lto_deduction_tax': lto_deduction_tax if tranche_record else 0,
        'lto_deduction_net': lto_deduction_net if tranche_record else 0,
    }
    
    return render(request, 'commission.html', context)

@login_required
def view_tranche_voucher(request, tranche_id):
    """Display tranche data in commission voucher format"""
    if not request.user.is_authenticated:
        return redirect('signin')
    
    # Get the tranche record
    record = get_object_or_404(TrancheRecord, id=tranche_id)
    
    # Check permissions - users can only view their own tranches unless superuser
    if not request.user.is_superuser and record.agent_name != request.user.get_full_name():
        messages.error(request, 'You do not have permission to view this tranche.')
        return redirect('tranche_history')
    
    # Calculate base values using the same logic as view_tranche
    vat_rate_decimal = record.vat_rate / Decimal(100)
    net_of_vat_base = record.total_contract_price / (Decimal(1) + vat_rate_decimal)
    less_process_fee = (net_of_vat_base * record.process_fee_percentage) / Decimal(100)
    total_selling_price = net_of_vat_base - less_process_fee
    tax_rate = record.withholding_tax_rate / Decimal(100)
    gross_commission = total_selling_price * (record.commission_rate / Decimal(100))
    
    vat_rate_decimal = record.vat_rate / Decimal(100)
    net_of_vat = gross_commission / (Decimal(1) + vat_rate_decimal)
    vat_amount = gross_commission - net_of_vat
    
    tax = net_of_vat * tax_rate
    withholding_tax_amount = tax
    net_commission = gross_commission - tax
    
    # Create a mock commission slip object for the template
    class MockTrancheSlip:
        def __init__(self, record, calculations):
            self.id = f"TRC-{record.id}"
            self.date = record.reservation_date.strftime('%B %d, %Y') if record.reservation_date else 'N/A'
            self.sales_agent_name = record.agent_name
            self.buyer_name = record.buyer_name
            self.project_name = record.project_name
            self.developer = record.project_name.split()[0] if record.project_name else 'N/A'  # Extract first word as developer
            self.release_number = f"TRC-{record.id}"
            self.payment_type = 'Tranche Payment'
            
            # Financial data from tranche calculations
            self.unit_id = getattr(record, 'unit_id', f"Unit-{record.id}")
            self.total_selling_price = calculations['total_selling_price']
            self.cash_advance = Decimal('0')  # Tranches don't have cash advance
            self.incentive_amount = 0
            
            # Additional tranche-specific fields
            self.lot_area = getattr(record, 'lot_area', 'N/A')
            self.floor_area = getattr(record, 'floor_area', 'N/A')
            self.tcp = record.total_contract_price
    
    # Create mock commission details
    class MockTrancheDetail:
        def __init__(self, record, calculations):
            self.position = 'Sales Agent'
            self.particulars = 'TRANCHE COMMISSION'
            self.commission_rate = record.commission_rate
            self.gross_commission = calculations['gross_commission']
            self.withholding_tax = calculations['withholding_tax_amount']
            self.net_commission = calculations['net_commission']
    
    # Prepare calculations for mock objects
    calculations = {
        'total_selling_price': total_selling_price,
        'gross_commission': gross_commission,
        'withholding_tax_amount': withholding_tax_amount,
        'net_commission': net_commission
    }
    
    mock_slip = MockTrancheSlip(record, calculations)
    mock_details = [MockTrancheDetail(record, calculations)]
    
    context = {
        'slip': mock_slip,
        'details': mock_details,
        'is_tranche_view': True,  # Flag to indicate this is a tranche view
        'tranche_record': record,
        'calculations': calculations,
    }
    
    return render(request, 'commission.html', context)

@login_required
def receivables(request):
    # Get filter parameters
    developer_filter = request.GET.get('developer', '')
    property_filter = request.GET.get('property', '')
    month_filter = request.GET.get('month', '')
    year_filter = request.GET.get('year', '')
    user_filter = request.GET.get('user', '')
    team_filter = request.GET.get('team', '')
    
    # Determine scope of data based on permissions
    if request.user.is_superuser:
        commission_entries = Commission.objects.all().order_by('-date_released')
        tranche_records = TrancheRecord.objects.all()
        user_full_name = None  # not used for superuser
    else:
        user_full_name = request.user.get_full_name()
        commission_entries = Commission.objects.filter(agent=request.user).order_by('-date_released')
        
        # Use robust agent lookup to find all tranche records that should belong to this user
        # This handles cases where agent_name in TrancheRecord doesn't exactly match user's full name
        user_name_variations = [
            user_full_name,
            request.user.username,
            f"{request.user.first_name} {request.user.last_name}".strip(),
            request.user.first_name,
            request.user.last_name
        ]
        
        # Filter out empty strings and create case-insensitive lookup
        valid_variations = [name for name in user_name_variations if name]
        tranche_records = TrancheRecord.objects.filter(
            agent_name__in=valid_variations
        ).distinct()
        
        # If no exact matches, try case-insensitive partial matching
        if not tranche_records.exists():
            q_objects = Q()
            for variation in valid_variations:
                q_objects |= Q(agent_name__icontains=variation)
            tranche_records = TrancheRecord.objects.filter(q_objects).distinct()
    
    # Apply developer/property filters
    if developer_filter:
        # Get all properties for this developer from the Property model
        from .models import Property
        developer_properties = Property.objects.filter(
            developer__name__icontains=developer_filter
        ).values_list('name', flat=True)
        
        print(f"DEBUG: Developer properties from Property model: {list(developer_properties)}")
        
        if developer_properties:
            # Filter commission entries by project names that belong to this developer
            commission_entries = commission_entries.filter(project_name__in=developer_properties)
            
            # Filter tranche records by matching project names
            tranche_records = tranche_records.filter(project_name__in=developer_properties)
        else:
            # No properties found for this developer
            commission_entries = commission_entries.none()
            tranche_records = tranche_records.none()
    
    if property_filter:
        commission_entries = commission_entries.filter(project_name__icontains=property_filter)
        tranche_records = tranche_records.filter(project_name__icontains=property_filter)
    
    # Apply date filters
    if year_filter:
        commission_entries = commission_entries.filter(date_released__year=year_filter)
        # For tranche records, include all records that have payments in the selected year (regardless of received amount)
        tranche_records = tranche_records.filter(
            payments__date_received__year=year_filter
        ).distinct()
    
    if month_filter:
        # If month is selected, apply month filter (with or without year)
        if year_filter:
            # Both year and month selected
            commission_entries = commission_entries.filter(
                date_released__year=year_filter,
                date_released__month=month_filter
            )
            # Filter tranche records by payments in specific year and month (regardless of received amount)
            tranche_records = tranche_records.filter(
                payments__date_received__year=year_filter,
                payments__date_received__month=month_filter
            ).distinct()
        else:
            # Only month selected (across all years)
            commission_entries = commission_entries.filter(date_released__month=month_filter)
            # Filter tranche records by payments in specific month (any year, regardless of received amount)
            tranche_records = tranche_records.filter(
                payments__date_received__month=month_filter
            ).distinct()
    
    # Apply user filter (only for superusers - regular users already see their own data)
    if user_filter and request.user.is_superuser:
        commission_entries = commission_entries.filter(agent__id=user_filter)
        # For tranche records, filter by agent name
        try:
            selected_user = User.objects.get(id=user_filter)
            user_name_variations = [
                selected_user.get_full_name(),
                selected_user.username,
                f"{selected_user.first_name} {selected_user.last_name}".strip(),
                selected_user.first_name,
                selected_user.last_name
            ]
            valid_variations = [name for name in user_name_variations if name]
            tranche_records = tranche_records.filter(agent_name__in=valid_variations)
        except User.DoesNotExist:
            pass

    # Apply team filter (only for superusers)
    if team_filter and request.user.is_superuser:
        try:
            selected_team = Team.objects.get(id=team_filter)
            # Filter commissions by agents in this team
            commission_entries = commission_entries.filter(agent__profile__team=selected_team)

            # For tranche records, build a list of agent full names for team members
            team_members = User.objects.filter(profile__team=selected_team, is_active=True)
            name_variations = []
            for member in team_members:
                variations = [
                    member.get_full_name(),
                    member.username,
                    f"{member.first_name} {member.last_name}".strip(),
                    member.first_name,
                    member.last_name
                ]
                name_variations.extend([n for n in variations if n])
            
            if name_variations:
                tranche_records = tranche_records.filter(agent_name__in=name_variations)
            else:
                # If no team members found or no valid name variations, return empty queryset
                tranche_records = tranche_records.none()
        except Team.DoesNotExist:
            # If team doesn't exist, return empty querysets
            commission_entries = commission_entries.none()
            tranche_records = tranche_records.none()
    
    # Get all unique developers and properties for filter dropdowns
    from .models import Developer
    
    if request.user.is_superuser:
        # Get developers from Developer model
        all_developers = list(Developer.objects.values_list('name', flat=True).order_by('name'))
        all_properties = Commission.objects.values_list('project_name', flat=True).distinct().order_by('project_name')
    else:
        # Get developers from Developer model
        all_developers = list(Developer.objects.values_list('name', flat=True).order_by('name'))
        all_properties = Commission.objects.filter(agent=request.user).values_list('project_name', flat=True).distinct().order_by('project_name')
    
    # Remove empty values and None for properties
    all_properties = [prop for prop in all_properties if prop and prop.strip()]
    
    # Get all users for user filter dropdown (only for superusers)
    all_users = []
    if request.user.is_superuser:
        all_users = User.objects.filter(
            is_active=True,
            commission__isnull=False
        ).distinct().order_by('first_name', 'last_name')

    # Get all teams for team filter dropdown (only for superusers)
    all_teams = []
    if request.user.is_superuser:
        all_teams = Team.objects.filter(is_active=True).order_by('name')
    
    # Get available years and months for date filters
    if request.user.is_superuser:
        available_years = Commission.objects.dates('date_released', 'year', order='DESC')
        available_months = Commission.objects.dates('date_released', 'month', order='DESC')
    else:
        available_years = Commission.objects.filter(agent=request.user).dates('date_released', 'year', order='DESC')
        available_months = Commission.objects.filter(agent=request.user).dates('date_released', 'month', order='DESC')
    
    # Extract unique years and months
    years_list = [date.year for date in available_years]
    months_list = []
    
    # If a year is selected, get months for that year only
    if year_filter:
        if request.user.is_superuser:
            year_months = Commission.objects.filter(date_released__year=year_filter).dates('date_released', 'month', order='ASC')
        else:
            year_months = Commission.objects.filter(agent=request.user, date_released__year=year_filter).dates('date_released', 'month', order='ASC')
        months_list = [(date.month, date.strftime('%B')) for date in year_months]
    else:
        # Get all months if no year is selected
        months_list = [(i, datetime(2000, i, 1).strftime('%B')) for i in range(1, 13)]

    # Calculate totals
    total_commission = sum(entry.commission_amount for entry in commission_entries)
    commission_count = commission_entries.count()

    # Calculate total remaining commission from tranches
    total_remaining = Decimal('0')

    # Create a dictionary to store project totals
    project_totals = {}
    
    # Debug: Add some logging to understand what's being filtered
    print(f"DEBUG: Developer filter: {developer_filter}")
    print(f"DEBUG: Commission entries count: {commission_entries.count()}")
    print(f"DEBUG: Tranche records count: {tranche_records.count()}")
    if developer_filter:
        print(f"DEBUG: Total commission for developer: {total_commission}")
        if commission_entries.exists():
            print(f"DEBUG: First commission entry: {commission_entries.first().project_name} - {commission_entries.first().developer}")
        if tranche_records.exists():
            print(f"DEBUG: First tranche record: {tranche_records.first().project_name}")

    # First pass: Calculate total expected commission for each project using EXACT same logic as view_tranche
    for record in tranche_records:
        project_key = f"{record.project_name}-{record.buyer_name}"
        if project_key not in project_totals:
            project_totals[project_key] = {
                'total_expected': Decimal('0'),
                'total_received': Decimal('0'),
                'payments': {}
            }

        # Get all payments for this tranche
        payments = record.payments.all()
        
        # Apply date filters to payments if they exist, but prioritize developer filter
        if developer_filter:
            # When developer filter is active, show all payments for that developer
            # regardless of date filters to show complete receivables picture
            filtered_payments = payments
        elif year_filter and month_filter:
            # Filter payments by specific year and month
            filtered_payments = payments.filter(
                date_received__year=year_filter,
                date_received__month=month_filter
            )
        elif year_filter:
            # Filter payments by year only
            filtered_payments = payments.filter(date_received__year=year_filter)
        elif month_filter:
            # Filter payments by month only (any year)
            filtered_payments = payments.filter(date_received__month=month_filter)
        else:
            # No date filter, use all payments
            filtered_payments = payments

        # *** USE EXACT SAME CALCULATION LOGIC AS view_tranche ***
        # Calculate base values using the Net of VAT divisor input field
        if record.net_of_vat_amount and record.net_of_vat_amount > 0:
            # Path 1: Use the manually entered Net of VAT divisor: TCP / Net of VAT divisor
            net_of_vat_base = (Decimal(str(record.total_contract_price)) / Decimal(str(record.net_of_vat_amount))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            less_process_fee = (net_of_vat_base * record.process_fee_percentage) / Decimal(100)
            total_selling_price = net_of_vat_base - less_process_fee
            gross_commission = total_selling_price * (record.commission_rate / Decimal(100))
        else:
            # Path 2: Use Total Contract Price directly when Net of VAT is 0 or empty
            net_of_vat_base = record.total_contract_price
            less_process_fee = record.total_contract_price * (record.process_fee_percentage / Decimal(100))
            total_selling_price = record.total_contract_price - less_process_fee
            gross_commission = total_selling_price * (record.commission_rate / Decimal(100))

        # Common calculations for both paths
        tax_rate = record.withholding_tax_rate / Decimal(100)
        vat_rate_decimal = record.vat_rate / Decimal(100)
        
        # Calculate VAT and Net of VAT from gross commission
        vat_amount = gross_commission * vat_rate_decimal
        net_of_vat = gross_commission - vat_amount
        
        # Calculate withholding tax and final net commission
        tax = net_of_vat * tax_rate
        net_commission = net_of_vat - tax

        # Calculate option1 values (DP period)
        option1_value_before_deduction = net_commission * (record.option1_percentage / Decimal(100))
        option1_tax_rate = record.option1_tax_rate / Decimal(100)

        # Apply deductions
        deduction_tax_rate = record.deduction_tax_rate / Decimal(100)
        deduction_tax = record.other_deductions * deduction_tax_rate
        deduction_net = record.other_deductions - deduction_tax

        option1_value = option1_value_before_deduction - deduction_net
        option1_monthly = option1_value / Decimal(record.number_months)

        # Calculate LTO values
        option2_value = net_commission * (record.option2_percentage / Decimal(100))
        option2_tax_rate = record.option2_tax_rate / Decimal(100)
        lto_deduction_value = option2_value
        lto_deduction_tax = lto_deduction_value * option2_tax_rate
        lto_deduction_net = lto_deduction_value - lto_deduction_tax
        lto_expected_commission = lto_deduction_net.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

        # Calculate accurate expected amounts for DP tranches
        dp_payments = filtered_payments.filter(is_lto=False)
        for payment in dp_payments:
            net = option1_monthly
            tax_amount = net * option1_tax_rate
            expected_commission = net - tax_amount
            
            key = f"DP-{record.id}-{payment.tranche_number}"
            project_totals[project_key]['payments'][key] = {
                'expected': expected_commission,
                'received': payment.received_amount
            }
            project_totals[project_key]['total_expected'] += expected_commission
            project_totals[project_key]['total_received'] += payment.received_amount

        # Calculate accurate expected amounts for LTO tranches
        lto_payments = filtered_payments.filter(is_lto=True)
        for payment in lto_payments:
            key = f"LTO-{record.id}-1"
            project_totals[project_key]['payments'][key] = {
                'expected': lto_expected_commission,
                'received': payment.received_amount
            }
            project_totals[project_key]['total_expected'] += lto_expected_commission
            project_totals[project_key]['total_received'] += payment.received_amount

    # Calculate total remaining using accurate expected values
    total_remaining = sum(
        project_info['total_expected'] - project_info['total_received']
        for project_info in project_totals.values()
    )

    # Prepare commission entries with payment type and completion percentage
    commissions_with_type = []
    for entry in commission_entries:
        project_record = None
        release_number_value = entry.release_number or ''

        # Try to extract a plausible TrancheRecord id from the release number safely
        parts = [p for p in str(release_number_value).split('-') if p]
        numeric_ids = []
        for part in parts:
            if part.isdigit():
                try:
                    numeric_ids.append(int(part))
                except ValueError:
                    pass

        if numeric_ids:
            project_record = tranche_records.filter(id__in=numeric_ids).first()

        project_info = {}
        completion_percentage = 0

        if project_record:
            project_key = f"{project_record.project_name}-{project_record.buyer_name}"
            project_info = project_totals.get(project_key, {})
            if project_info and project_info.get('total_expected', 0) > 0:
                completion_percentage = (project_info.get('total_received', 0) / project_info.get('total_expected', 0)) * 100

        commissions_with_type.append({
            'date_released': entry.date_released,
            'release_number': entry.release_number,
            'project_name': entry.project_name,
            'developer': entry.developer,
            'buyer': entry.buyer,
            'agent_name': entry.agent.get_full_name() or entry.agent.username,
            'commission_amount': entry.commission_amount,
            'payment_type': 'Loan Take Out' if 'LTO' in release_number_value else 'Down Payment',
            'completion_percentage': completion_percentage,
            'total_expected': project_info.get('total_expected', 0),
            'total_received': project_info.get('total_received', 0)
        })

    # --- Pagination ---
    paginator = Paginator(commissions_with_type, 25)  # 25 rows per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Calculate counts for the chart
    dp_count = sum(1 for comm in commissions_with_type if comm['payment_type'] == 'Down Payment')
    lto_count = sum(1 for comm in commissions_with_type if comm['payment_type'] == 'Loan Take Out')

    # --- Monthly Trend Chart Data (with filters applied) ---
    six_months_ago = timezone.now() - timedelta(days=180)
    monthly_query = commission_entries.filter(date_released__gte=six_months_ago)
    monthly_data = (
        monthly_query
        .annotate(month=TruncMonth('date_released'))
        .values('month')
        .annotate(total=Sum('commission_amount'))
        .order_by('month')
    )

    # Prepare data for Chart.js, ensuring we have data for the last 6 months
    month_map = {data['month'].strftime('%b'): data['total'] for data in monthly_data}
    monthly_labels = []
    monthly_collections = []
    for i in range(5, -1, -1):
        month_date = timezone.now() - timedelta(days=i*30)
        month_name = month_date.strftime('%b')
        if month_name not in monthly_labels:
            monthly_labels.append(month_name)
            monthly_collections.append(float(month_map.get(month_name, 0)))

    # Calculate total commissions (received + remaining)
    total_commissions = total_commission + total_remaining

    context = {
        'page_obj': page_obj,
        'commission_count': commission_count,
        'total_commission': total_commission,
        'total_remaining': total_remaining,
        'total_commissions': total_commissions,
        'dp_count': dp_count,
        'lto_count': lto_count,
        'monthly_labels': monthly_labels,
        'monthly_collections': monthly_collections,
        'all_developers': all_developers,
        'all_properties': all_properties,
        'selected_developer': developer_filter,
        'selected_property': property_filter,
        'available_years': years_list,
        'available_months': months_list,
        'selected_year': year_filter,
        'selected_month': month_filter,
        'all_users': all_users,
        'selected_user': user_filter,
        'all_teams': all_teams,
        'selected_team': team_filter,
    }
    return render(request, 'receivables.html', context)

@login_required
def edit_commission(request, commission_id):
    commission = get_object_or_404(Commission, id=commission_id, agent=request.user)
    if request.method == 'POST':
        commission.date_released = request.POST.get('date_released')
        commission.release_number = request.POST.get('release_number')
        commission.project_name = request.POST.get('project_name')
        commission.developer = request.POST.get('developer')
        commission.buyer = request.POST.get('buyer')
        commission.commission_amount = request.POST.get('commission_amount')
        commission.save()
        messages.success(request, 'Commission updated successfully!')
        return redirect('receivables')
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    }, status=400)

class CustomPasswordResetView(PasswordResetView):
    template_name = 'password/password_reset.html'
    email_template_name = 'password/password_reset_email.html'
    subject_template_name = 'password/password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')
    from_email = settings.DEFAULT_FROM_EMAIL

class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'password/password_reset_done.html'

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'password/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')

class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'password/password_reset_complete.html'
    
    def get_success_url(self):
        return reverse_lazy('signin')

@csrf_protect
@require_http_methods(["POST"])
def update_tranche(request):
    try:
        data = json.loads(request.body)
        tranche_number = data.get('tranche_number')
        received_amount = data.get('received_amount')
        date_received = data.get('date_received')
        is_lto = data.get('is_lto')

        # Get the tranche payment
        tranche = TranchePayment.objects.get(
            tranche_number=tranche_number,
            is_lto=is_lto
        )

        # Update the tranche
        tranche.received_amount = received_amount
        tranche.date_received = datetime.strptime(date_received, '%Y-%m-%d').date()
        
        # Update status based on received amount
        if received_amount >= tranche.expected_amount:
            tranche.status = 'Received'
        elif received_amount > 0:
            tranche.status = 'Partial'
        else:
            tranche.status = 'Pending'
            
        tranche.save()

        return JsonResponse({
            'success': True,
            'message': 'Tranche updated successfully',
            'balance': float(tranche.expected_amount - tranche.received_amount)
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        }, status=400)

@login_required(login_url='signin')
def change_role(request, profile_id):
    if not (request.user.is_superuser or request.user.profile.role == 'Sales Manager'):
        return HttpResponseForbidden()

    profile = get_object_or_404(Profile, id=profile_id)
    
    if request.method == 'POST':
        new_role = request.POST.get('role')
        
        # Only superusers can assign Sales Manager role
        if new_role == 'Sales Manager' and not request.user.is_superuser:
            messages.error(request, 'Only superusers can assign Sales Manager role')
            return redirect('approve')
            
        # Sales Managers can only modify Sales Supervisor and Sales Agent roles
        if not request.user.is_superuser and profile.role not in ['Sales Supervisor', 'Sales Agent']:
            messages.error(request, 'You can only modify roles for Sales Supervisors and Sales Agents')
            return redirect('approve')
        
        # Validate the role
        if new_role in ['Sales Manager', 'Sales Supervisor', 'Sales Agent']:
            profile.role = new_role
            profile.save()
            messages.success(request, f'Role updated to {new_role}')
        else:
            messages.error(request, 'Invalid role selection')
    
    return redirect('approve')

@login_required(login_url='signin')
def change_team(request, profile_id):
    # Only superusers can change team
    if not request.user.is_superuser:
        return HttpResponseForbidden()
    
    profile = get_object_or_404(Profile, id=profile_id)
    if request.method == 'POST':
        new_team_id = request.POST.get('team')
        try:
            new_team = Team.objects.get(id=new_team_id)
            profile.team = new_team
            profile.save()
            messages.success(request, f'Team updated to {new_team.display_name or new_team.name}')
        except Team.DoesNotExist:
            messages.error(request, 'Selected team does not exist')
    
    return redirect('approve')

@login_required
def toggle_staff_status(request, user_id):
    if not request.user.is_superuser:
        return HttpResponseForbidden()
    
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        user.is_staff = not user.is_staff
        user.save()
        status = 'granted' if user.is_staff else 'removed'
        messages.success(request, f'Staff status {status} for {user.username}')
    return redirect('approve')

@login_required
@require_http_methods(["GET", "POST"])
def delete_profile(request, profile_id):
    if not request.user.is_superuser:
        return HttpResponseForbidden("You don't have permission to delete profiles.")
    
    profile = get_object_or_404(Profile, id=profile_id)
    user = profile.user
    
    # Don't allow superusers to be deleted through this interface
    if user.is_superuser:
        messages.error(request, "Superuser accounts cannot be deleted through this interface.")
        return redirect('approve')
    
    if request.method == "POST":
        try:
            # Store username for the success message
            username = user.username
            
            # Delete the user (this will cascade delete the profile)
            user.delete()
            
            messages.success(request, f"Profile and user account for {username} have been deleted successfully.")
        except Exception as e:
            messages.error(request, f"Error deleting profile: {str(e)}")
    
        return redirect('approve')
    else:
        # Show confirmation page for GET request
        return render(request, 'confirm_delete.html', {
            'profile': profile,
            'user_to_delete': user
        })

@login_required(login_url='signin')
def tranche_history(request):
    # Get filter parameters
    developer_filter = request.GET.get('developer', '')
    property_filter = request.GET.get('property', '')
    month_filter = request.GET.get('month', '')
    year_filter = request.GET.get('year', '')
    user_filter = request.GET.get('user', '')
    team_filter = request.GET.get('team', '')
    
    # Base queryset
    tranche_records = TrancheRecord.objects.all()
    
    # Filter based on user role and permissions
    if request.user.is_superuser:
        # Superusers can see all records initially
        pass
    elif request.user.is_staff:
        # Staff can see:
        # 1. Records they created
        # 2. Records where they are the agent
        # 3. Records for agents in their team
        user_team = request.user.profile.team
        team_members = User.objects.filter(
            profile__team=user_team,
            profile__is_approved=True
        ).values_list('first_name', 'last_name')
        team_full_names = [f"{first} {last}".strip() for first, last in team_members]
        
        tranche_records = tranche_records.filter(
            Q(created_by=request.user) |  # Records they created
            Q(agent_name=request.user.get_full_name()) |  # Records where they are the agent
            Q(agent_name__in=team_full_names)  # Records for their team members
        ).distinct()
    else:
        # Regular users can only see their own records
        tranche_records = tranche_records.filter(
            agent_name=request.user.get_full_name()
        )
    
    # Apply filters before ordering
    # Apply developer/property filters
    if developer_filter:
        # Filter by developer name using Property model relationship
        from .models import Property
        
        # Get all properties that belong to the selected developer
        developer_properties = Property.objects.filter(
            developer__name__icontains=developer_filter
        ).values_list('name', flat=True)
        
        if developer_properties:
            # Filter tranche records by matching project names with developer's properties
            property_query = Q()
            for prop_name in developer_properties:
                property_query |= Q(project_name__icontains=prop_name)
            tranche_records = tranche_records.filter(property_query)
        else:
            # If no properties found for this developer, return empty queryset
            tranche_records = tranche_records.none()
    
    if property_filter:
        tranche_records = tranche_records.filter(project_name__icontains=property_filter)
    
    # Apply date filters (filter by created_at date)
    if year_filter:
        tranche_records = tranche_records.filter(created_at__year=year_filter)
    
    if month_filter:
        if year_filter:
            tranche_records = tranche_records.filter(
                created_at__year=year_filter,
                created_at__month=month_filter
            )
        else:
            tranche_records = tranche_records.filter(created_at__month=month_filter)
    
    # Apply user filter (only for superusers)
    if user_filter and request.user.is_superuser:
        try:
            selected_user = User.objects.get(id=user_filter)
            user_name_variations = [
                selected_user.get_full_name(),
                selected_user.username,
                f"{selected_user.first_name} {selected_user.last_name}".strip(),
                selected_user.first_name,
                selected_user.last_name
            ]
            valid_variations = [name for name in user_name_variations if name]
            tranche_records = tranche_records.filter(agent_name__in=valid_variations)
        except User.DoesNotExist:
            pass
    
    # Apply team filter (only for superusers)
    if team_filter and request.user.is_superuser:
        try:
            # Get the team object by name (team_filter is team name from template)
            from .models import Team
            selected_team = Team.objects.get(name=team_filter, is_active=True)
            
            # Get all users in the selected team
            team_members = User.objects.filter(
                profile__team=selected_team,
                profile__is_approved=True
            )
            
            if team_members.exists():
                # Create name variations for exact and partial matching
                team_name_variations = []
                for member in team_members:
                    variations = [
                        member.get_full_name(),
                        f"{member.first_name} {member.last_name}".strip(),
                        member.username,
                        member.first_name,
                        member.last_name
                    ]
                    # Add non-empty variations
                    valid_variations = [name for name in variations if name]
                    team_name_variations.extend(valid_variations)
                
                if team_name_variations:
                    # First try exact matches
                    exact_match_query = Q()
                    for name in team_name_variations:
                        exact_match_query |= Q(agent_name__iexact=name)
                    
                    filtered_records = tranche_records.filter(exact_match_query)
                    
                    # If no exact matches, try case-insensitive partial matching
                    if not filtered_records.exists():
                        partial_match_query = Q()
                        for name in team_name_variations:
                            partial_match_query |= Q(agent_name__icontains=name)
                        
                        # Use the already filtered tranche_records queryset instead of starting fresh
                        # This preserves all previously applied filters (developer, property, date, etc.)
                        filtered_records = tranche_records.filter(partial_match_query).distinct()
                    
                    tranche_records = filtered_records
                else:
                    tranche_records = tranche_records.none()
            else:
                # If no team members found, return empty queryset
                tranche_records = tranche_records.none()
                
        except (Team.DoesNotExist, ValueError):
            # If team doesn't exist or invalid ID, return empty queryset
            tranche_records = tranche_records.none()
    
    # Order by most recent first
    tranche_records = tranche_records.order_by('-created_at')
    
    # Calculate payment statistics for each record
    records_with_stats = []
    for record in tranche_records:
        total_payments = record.payments.count()
        received_payments = record.payments.filter(status='Received').count()
        
        status = 'Pending'
        if received_payments == total_payments and total_payments > 0:
            status = 'Completed'
        elif received_payments > 0:
            status = 'In Progress'
            
        records_with_stats.append({
            'record': record,
            'total_payments': total_payments,
            'received_payments': received_payments,
            'status': status,
            'completion_percentage': (received_payments / total_payments * 100) if total_payments > 0 else 0
        })
    
    # Calculate overall statistics
    total_records = len(records_with_stats)
    active_tranches = sum(1 for r in records_with_stats if r['status'] == 'In Progress')
    total_contract_value = sum(r['record'].total_contract_price for r in records_with_stats)
    
    # Calculate total commission values
    total_gross_commission = Decimal('0')
    total_net_commission = Decimal('0')
    
    for r in records_with_stats:
        record = r['record']
        
        # Calculate gross commission using same logic as view_tranche
        if record.net_of_vat_amount and record.net_of_vat_amount > 0:
            # Path 1: Use the manually entered Net of VAT divisor
            net_of_vat_base = (Decimal(str(record.total_contract_price)) / Decimal(str(record.net_of_vat_amount))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            less_process_fee = (net_of_vat_base * record.process_fee_percentage) / Decimal(100)
            total_selling_price = net_of_vat_base - less_process_fee
            gross_commission = total_selling_price * (record.commission_rate / Decimal(100))
        else:
            # Path 2: Use Total Contract Price directly
            net_of_vat_base = record.total_contract_price
            less_process_fee = record.total_contract_price * (record.process_fee_percentage / Decimal(100))
            total_selling_price = record.total_contract_price - less_process_fee
            gross_commission = total_selling_price * (record.commission_rate / Decimal(100))
        
        # Calculate net commission
        vat_rate_decimal = record.vat_rate / Decimal(100)
        vat_amount = gross_commission * vat_rate_decimal
        net_of_vat = gross_commission - vat_amount
        withholding_tax_amount = net_of_vat * (record.withholding_tax_rate / Decimal(100))
        net_commission = net_of_vat - withholding_tax_amount
        
        total_gross_commission += gross_commission
        total_net_commission += net_commission
    
    # Get filter dropdown data
    # Get all unique developers and properties for filter dropdowns
    from .models import Developer, Property
    
    if request.user.is_superuser:
        project_names = TrancheRecord.objects.values_list('project_name', flat=True).distinct().order_by('project_name')
        all_properties = [proj for proj in project_names if proj and proj.strip()]
        
        # Get developers from Developer model
        all_developers = list(Developer.objects.values_list('name', flat=True).order_by('name'))
    else:
        user_records = TrancheRecord.objects.filter(agent_name=request.user.get_full_name())
        project_names = user_records.values_list('project_name', flat=True).distinct().order_by('project_name')
        all_properties = [proj for proj in project_names if proj and proj.strip()]
        
        # Get developers from Developer model
        all_developers = list(Developer.objects.values_list('name', flat=True).order_by('name'))
    
    # Get all users for user filter dropdown (only for superusers)
    all_users = []
    if request.user.is_superuser:
        all_users = User.objects.filter(
            is_active=True,
            profile__is_approved=True
        ).distinct().order_by('first_name', 'last_name')
    
    # Get all teams for team filter dropdown (only for superusers)
    all_teams = []
    if request.user.is_superuser:
        from .models import Team
        all_teams = Team.objects.filter(is_active=True).order_by('name')
    
    # Get available years and months for date filters
    if request.user.is_superuser:
        available_years = TrancheRecord.objects.dates('created_at', 'year', order='DESC')
        available_months = TrancheRecord.objects.dates('created_at', 'month', order='DESC')
    else:
        user_records = TrancheRecord.objects.filter(agent_name=request.user.get_full_name())
        available_years = user_records.dates('created_at', 'year', order='DESC')
        available_months = user_records.dates('created_at', 'month', order='DESC')
    
    # Extract unique years and months
    years_list = [date.year for date in available_years]
    months_list = []
    
    # If a year is selected, get months for that year only
    if year_filter:
        if request.user.is_superuser:
            year_months = TrancheRecord.objects.filter(created_at__year=year_filter).dates('created_at', 'month', order='ASC')
        else:
            year_months = TrancheRecord.objects.filter(agent_name=request.user.get_full_name(), created_at__year=year_filter).dates('created_at', 'month', order='ASC')
        months_list = [(date.month, date.strftime('%B')) for date in year_months]
    else:
        # Get all months if no year is selected
        months_list = [(i, datetime(2000, i, 1).strftime('%B')) for i in range(1, 13)]

    # --- Pagination ---
    paginator = Paginator(records_with_stats, 25)  # 25 rows per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'total_records': total_records,
        'active_tranches': active_tranches,
        'total_contract_value': total_contract_value,
        'total_gross_commission': total_gross_commission,
        'total_net_commission': total_net_commission,
        'user_full_name': request.user.get_full_name(),
        'user_team': request.user.profile.team if hasattr(request.user, 'profile') else None,
        'all_developers': all_developers,
        'all_properties': all_properties,
        'selected_developer': developer_filter,
        'selected_property': property_filter,
        'available_years': years_list,
        'available_months': months_list,
        'selected_year': year_filter,
        'selected_month': month_filter,
        'all_users': all_users,
        'selected_user': user_filter,
        'all_teams': all_teams,
        'selected_team': team_filter,
    }
    return render(request, 'tranche_history.html', context)

@register.filter
def format_tranche_option(value):
    """Convert tranche option from snake_case to Title Case"""
    return value.replace('_', ' ').title()

@login_required(login_url='signin')
def view_tranche(request, tranche_id):
    # Get the tranche record
    record = get_object_or_404(TrancheRecord, id=tranche_id)

    # Check if user has permission to view this tranche
    if request.user.profile.role == 'Sales Agent' and record.agent_name != request.user.get_full_name():
        messages.error(request, 'You do not have permission to view this tranche.')
        return redirect('tranche_history')

    # Format tranche option
    formatted_tranche_option = record.tranche_option.replace('_', ' ').title()

    # Calculate base values using the Net of VAT divisor input field
    # If net_of_vat_amount is provided, use it as divisor; otherwise use Total Contract Price directly
    if record.net_of_vat_amount and record.net_of_vat_amount > 0:
        # Path 1: Use the manually entered Net of VAT divisor: TCP / Net of VAT divisor
        net_of_vat_base = (Decimal(str(record.total_contract_price)) / Decimal(str(record.net_of_vat_amount))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        less_process_fee = (net_of_vat_base * record.process_fee_percentage) / Decimal(100)
        total_selling_price = net_of_vat_base - less_process_fee
        gross_commission = total_selling_price * (record.commission_rate / Decimal(100))
    else:
        # Path 2: Use Total Contract Price directly when Net of VAT is 0 or empty
        net_of_vat_base = record.total_contract_price
        less_process_fee = record.total_contract_price * (record.process_fee_percentage / Decimal(100))
        total_selling_price = record.total_contract_price - less_process_fee
        gross_commission = total_selling_price * (record.commission_rate / Decimal(100))

    # Common calculations for both paths
    tax_rate = record.withholding_tax_rate / Decimal(100)
    vat_rate_decimal = record.vat_rate / Decimal(100)
    
    # Calculate VAT and Net of VAT from gross commission
    vat_amount = gross_commission * vat_rate_decimal
    net_of_vat = gross_commission - vat_amount
    
    # Calculate withholding tax and final net commission
    tax = net_of_vat * tax_rate
    withholding_tax_amount = tax
    net_of_withholding_tax = net_of_vat - withholding_tax_amount
    net_commission = net_of_vat - tax

    # Get DP tranches and calculate values
    dp_payments = record.payments.filter(is_lto=False).order_by('tranche_number')
    dp_tranches = []
    total_net = Decimal('0')
    total_dp_tax = Decimal('0')

    # Calculate option1 values (DP period)
    option1_value_before_deduction = net_commission * (record.option1_percentage / Decimal(100))
    option1_tax_rate = record.option1_tax_rate / Decimal(100)

    # Apply deductions
    deduction_tax_rate = record.deduction_tax_rate / Decimal(100)
    deduction_tax = record.other_deductions * deduction_tax_rate
    deduction_net = record.other_deductions - deduction_tax

    option1_value = option1_value_before_deduction - deduction_net
    option1_monthly = option1_value / Decimal(record.number_months)

    # Calculate totals for DP period
    total_expected_commission = Decimal('0')
    for payment in dp_payments:
        net = option1_monthly
        tax_amount = net * option1_tax_rate
        expected_commission = net - tax_amount
        total_expected_commission += expected_commission

        dp_tranches.append({
            'tranche': payment,
            'tax_amount': tax_amount,
            'net_amount': net,
            'expected_commission': expected_commission,
            'balance': expected_commission - payment.received_amount,
            'initial_balance': payment.initial_balance
        })
        total_net += net
        total_dp_tax += tax_amount

    # Calculate LTO values
    option2_value = net_commission * (record.option2_percentage / Decimal(100))
    option2_tax_rate = record.option2_tax_rate / Decimal(100)
    lto_deduction_value = option2_value
    lto_deduction_tax = lto_deduction_value * option2_tax_rate
    # Net amount after tax deduction
    lto_deduction_net = lto_deduction_value - lto_deduction_tax
    # Expected commission for the LTO tranche should be the net amount (same value shown in templates)
    lto_expected_commission = lto_deduction_net.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

    # Get LTO tranche
    lto_payment = record.payments.filter(is_lto=True).first()
    lto_tranches = []
    if lto_payment:
        lto_tranches.append({
            'tranche': lto_payment,
            'tax_amount': lto_deduction_tax,
            'net_amount': lto_deduction_net,
            'expected_commission': lto_expected_commission,
            'balance': lto_expected_commission - lto_payment.received_amount,
            'initial_balance': lto_payment.initial_balance
        })

    # Calculate totals
    total_commission1 = total_expected_commission
    total_commission_received = sum(t['tranche'].received_amount for t in dp_tranches)
    total_balance = total_commission1 - total_commission_received
    percentage_received = (total_commission_received / total_commission1 * 100) if total_commission1 > 0 else 0
    percentage_remaining = 100 - percentage_received

    total_commission2 = sum(t['tranche'].expected_amount for t in lto_tranches)
    total_commission_received2 = sum(t['tranche'].received_amount for t in lto_tranches)
    total_balance2 = total_commission2 - total_commission_received2
    percentage_received2 = (total_commission_received2 / total_commission2 * 100) if total_commission2 > 0 else 0
    percentage_remaining2 = 100 - percentage_received2

    context = {
        'record': record,
        'total_contract_price': record.total_contract_price,
        'less_process_fee': less_process_fee,
        'net_of_vat_amount': net_of_vat_base,  # Use net_of_vat_base (from TCP) instead of record.net_of_vat_amount
        'total_selling_price': total_selling_price,
        'commission_rate': record.commission_rate,
        'gross_commission': gross_commission,
        'vat_rate': record.vat_rate,
        'net_of_vat': net_of_vat,  # This is for commission-based Net of VAT
        'withholding_tax_rate': record.withholding_tax_rate,
        'withholding_tax_amount': withholding_tax_amount,
        'net_of_withholding_tax': net_of_withholding_tax,
        'vat_amount': vat_amount,
        'tax': tax_rate * 100,
        'tax_rate': tax,
        'net_commission': net_commission,
        'dp_tranches': dp_tranches,
        'lto_tranches': lto_tranches,
        'option1_value': option1_value,
        'option1_value_before_deduction': option1_value_before_deduction,
        'option2_value': option2_value,
        'option1_percentage': record.option1_percentage,
        'option2_percentage': record.option2_percentage,
        'option1_tax_rate': option1_tax_rate,
        'option2_tax_rate': option2_tax_rate,
        'tranche_option': formatted_tranche_option,
        'number_months': record.number_months,
        'process_fee_percentage': record.process_fee_percentage,
        'option1_monthly': option1_monthly,
        'total_commission1': total_commission1,
        'total_commission_received': total_commission_received,
        'total_balance': total_balance,
        'percentage_received': percentage_received,
        'percentage_remaining': percentage_remaining,
        'other_deductions': record.other_deductions,
        'deduction_type': record.deduction_type,
        'deduction_tax': deduction_tax,
        'deduction_net': deduction_net,
        'deductions': option1_value,
        'deduction_tax_rate': deduction_tax_rate * 100,
        'total_commission2': total_commission2,
        'total_commission_received2': total_commission_received2,
        'total_balance2': total_balance2,
        'percentage_received2': percentage_received2,
        'percentage_remaining2': percentage_remaining2,
        'total_dp_tax': total_dp_tax,
        'lto_deduction_value': lto_deduction_value,
        'lto_deduction_tax': lto_deduction_tax,
        'lto_deduction_net': lto_deduction_net,
    }

    return render(request, 'view_tranche.html', context)

@login_required(login_url='signin')
def edit_tranche(request, tranche_id):
    # Get the tranche record
    record = get_object_or_404(TrancheRecord, id=tranche_id)

    # Check if user has permission to edit this tranche
    if not (request.user.is_superuser or request.user.profile.role in ['Sales Manager', 'Sales Supervisor']):
        messages.error(request, 'You do not have permission to edit tranches.')
        return redirect('tranche_history')

    if request.method == 'POST':
        try:
            # --- Update basic tranche details ---
            record.project_name = request.POST.get('project_name', record.project_name)
            record.agent_name = request.POST.get('agent_name', record.agent_name)
            record.buyer_name = request.POST.get('buyer_name', record.buyer_name)
            # Safely convert numeric fields
            from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
            def _to_decimal(val, default):
                try:
                    return Decimal(val)
                except (InvalidOperation, TypeError):
                    return default
            record.total_contract_price = _to_decimal(request.POST.get('total_contract_price'), record.total_contract_price)
            record.commission_rate = _to_decimal(request.POST.get('commission_rate'), record.commission_rate)
            record.save()

            # --- Update payment records and create commission entries ---
            for payment in record.payments.all():
                received_amount = request.POST.get(f'received_amount_{payment.id}')
                date_received = request.POST.get(f'date_received_{payment.id}')
                old_received_amount = payment.received_amount
                old_date_received = payment.date_received

                if received_amount:
                    payment.received_amount = Decimal(received_amount)
                    if date_received:
                        payment.date_received = datetime.strptime(date_received, '%Y-%m-%d').date()

                    # Update status based on received amount
                    if payment.received_amount >= payment.expected_amount:
                        payment.status = 'Received'
                    elif payment.received_amount > 0:
                        payment.status = 'Partial'
                    else:
                        payment.status = 'Pending'

                    payment.save()

                    # Only create/update commission if there's a new payment or date change
                    if (payment.received_amount != old_received_amount or
                        payment.date_received != old_date_received) and payment.received_amount > 0:

                        # Find the agent user with improved lookup logic
                        try:
                            agent_user = find_agent_user_by_name(record.agent_name)

                            if agent_user:
                                # Create or update commission record
                                release_code = f"LTO-{record.id}-1" if payment.is_lto else f"DP-{record.id}-{payment.tranche_number}"

                                # Check for existing commission
                                existing_commission = Commission.objects.filter(
                                    release_number=release_code,
                                    agent=agent_user
                                ).first()

                                if existing_commission:
                                    # Update existing commission with the actual received amount
                                    existing_commission.commission_amount = payment.received_amount
                                    existing_commission.date_released = payment.date_received
                                    existing_commission.save()
                                    logger.info(f'Updated commission for {agent_user.get_full_name()}: {release_code} - ₱{payment.received_amount}')
                                else:
                                    # Create new commission with the actual received amount
                                    new_commission = Commission.objects.create(
                                        date_released=payment.date_received,
                                        release_number=release_code,
                                        project_name=record.project_name,
                                        developer=record.project_name.split()[0],  # Using first word as developer
                                        buyer=record.buyer_name,
                                        agent=agent_user,
                                        commission_amount=payment.received_amount
                                    )
                                    logger.info(f'Created new commission for {agent_user.get_full_name()}: {release_code} - ₱{payment.received_amount}')
                            else:
                                # Log detailed information about the failed lookup
                                available_users = [f"{u.get_full_name()} ({u.username})" for u in User.objects.filter(is_active=True)]
                                logger.warning(f'Could not find user account for agent: "{record.agent_name}". Available active users: {available_users}')
                                messages.warning(request, f'Could not find user account for agent: "{record.agent_name}". Please verify the agent name matches an active user account.')

                        except Exception as e:
                            logger.error(f'Error finding agent user for {record.agent_name}: {str(e)}')
                            messages.error(request, f'Error processing commission for agent: {record.agent_name} - {str(e)}')

            messages.success(request, 'Tranche record and commissions updated successfully!')
            return redirect('view_tranche', tranche_id=tranche_id)

        except Exception as e:
            messages.error(request, f'Error updating tranche record: {str(e)}')

    # For GET request or if there's an error in POST
    # ----- Use EXACT same calculation logic as view_tranche -----
    from decimal import Decimal, ROUND_HALF_UP

    # Calculate base values using the Net of VAT divisor input field (EXACT same as view_tranche)
    # If net_of_vat_amount is provided, use it as divisor; otherwise use Total Contract Price directly
    if record.net_of_vat_amount and record.net_of_vat_amount > 0:
        # Path 1: Use the manually entered Net of VAT divisor: TCP / Net of VAT divisor
        net_of_vat_base = (Decimal(str(record.total_contract_price)) / Decimal(str(record.net_of_vat_amount))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        less_process_fee = (net_of_vat_base * record.process_fee_percentage) / Decimal(100)
        total_selling_price = net_of_vat_base - less_process_fee
        gross_commission = total_selling_price * (record.commission_rate / Decimal(100))
    else:
        # Path 2: Use Total Contract Price directly when Net of VAT is 0 or empty
        net_of_vat_base = record.total_contract_price
        less_process_fee = record.total_contract_price * (record.process_fee_percentage / Decimal(100))
        total_selling_price = record.total_contract_price - less_process_fee
        gross_commission = total_selling_price * (record.commission_rate / Decimal(100))

    # Common calculations for both paths (EXACT same as view_tranche)
    tax_rate = record.withholding_tax_rate / Decimal(100)
    vat_rate_decimal = record.vat_rate / Decimal(100)
    
    # Calculate VAT and Net of VAT from gross commission
    vat_amount = gross_commission * vat_rate_decimal
    net_of_vat = gross_commission - vat_amount
    
    # Calculate withholding tax and final net commission
    tax = net_of_vat * tax_rate
    withholding_tax_amount = tax
    net_of_withholding_tax = net_of_vat - withholding_tax_amount
    net_commission = net_of_vat - tax

    # Get DP tranches and calculate values (EXACT same as view_tranche)
    dp_payments = record.payments.filter(is_lto=False).order_by('tranche_number')
    dp_tranches = []
    total_net = Decimal('0')
    total_dp_tax = Decimal('0')

    # Calculate option1 values (DP period)
    option1_value_before_deduction = net_commission * (record.option1_percentage / Decimal(100))
    option1_tax_rate = record.option1_tax_rate / Decimal(100)

    # Apply deductions
    deduction_tax_rate = record.deduction_tax_rate / Decimal(100)
    deduction_tax = record.other_deductions * deduction_tax_rate
    deduction_net = record.other_deductions - deduction_tax

    option1_value = option1_value_before_deduction - deduction_net
    option1_monthly = option1_value / Decimal(record.number_months)

    # Calculate totals for DP period
    total_expected_commission = Decimal('0')
    for payment in dp_payments:
        net = option1_monthly
        tax_amount = net * option1_tax_rate
        expected_commission = net - tax_amount
        total_expected_commission += expected_commission

        dp_tranches.append({
            'tranche': payment,
            'tax_amount': tax_amount,
            'net_amount': net,
            'expected_commission': expected_commission,
            'balance': expected_commission - payment.received_amount,
            'initial_balance': payment.initial_balance
        })
        total_net += net
        total_dp_tax += tax_amount

    # Calculate LTO values (EXACT same as view_tranche)
    option2_value = net_commission * (record.option2_percentage / Decimal(100))
    option2_tax_rate = record.option2_tax_rate / Decimal(100)
    lto_deduction_value = option2_value
    lto_deduction_tax = lto_deduction_value * option2_tax_rate
    # Net amount after tax deduction
    lto_deduction_net = lto_deduction_value - lto_deduction_tax
    # Expected commission for the LTO tranche should be the net amount (same value shown in templates)
    lto_expected_commission = lto_deduction_net.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

    # Get LTO tranche
    lto_payment = record.payments.filter(is_lto=True).first()
    lto_tranches = []
    if lto_payment:
        lto_tranches.append({
            'tranche': lto_payment,
            'tax_amount': lto_deduction_tax,
            'net_amount': lto_deduction_net,
            'expected_commission': lto_expected_commission,
            'balance': lto_expected_commission - lto_payment.received_amount,
            'initial_balance': lto_payment.initial_balance
        })

    return render(request, 'edit_tranche.html', {
        'record': record,
        'dp_tranches': dp_tranches,
        'lto_tranches': lto_tranches,
        'option1_percentage': record.option1_percentage,
        'option2_percentage': record.option2_percentage,
        'option1_tax_rate': option1_tax_rate,
        'option2_tax_rate': option2_tax_rate,
        'lto_deduction_value': lto_deduction_value,
        'lto_deduction_tax': lto_deduction_tax,
        'lto_deduction_net': lto_deduction_net,
        'lto_expected_commission': lto_expected_commission,
        'total_expected_commission': total_expected_commission,
        'option1_monthly': option1_monthly,
        'net_commission': net_commission,
        'gross_commission': gross_commission,
        'vat_amount': vat_amount,
        'withholding_tax_amount': withholding_tax_amount,
        'total_selling_price': total_selling_price,
        'less_process_fee': less_process_fee,
        'net_of_vat_base': net_of_vat_base,
    })

@register.filter
def filter_received(tranches):
    return [t for t in tranches if t['tranche'].status == 'Received']

@register.filter
def next_due_tranche(tranches):
    for tranche in tranches:
        if tranche['tranche'].status != 'Received':
            return tranche['tranche']
    return None

@register.filter
def last_paid_tranche(tranches):
    paid_tranches = [t['tranche'] for t in tranches if t['tranche'].date_received]
    return max(paid_tranches, key=lambda x: x.date_received) if paid_tranches else None

@register.filter
def replace(value, arg):
    """Replace all instances of arg in the string with spaces"""
    return value.replace(arg, " ")

@login_required(login_url='signin')
def create_commission_slip3(request):
    if not request.user.is_active:
        messages.error(request, "Your account is not active.")
        return redirect('signin')

    # Get the current user's profile
    user_profile = request.user.profile

    # Filter users based on role and permissions
    if request.user.is_superuser or request.user.is_staff:
        # Superusers and staff can see all active agents and supervisors from all teams
        active_agents = User.objects.filter(
            is_active=True,
            profile__role='Sales Agent',
            profile__is_approved=True
        ).order_by('username')
        active_supervisors = User.objects.filter(
            is_active=True,
            profile__role='Sales Supervisor',
            profile__is_approved=True
        ).order_by('username')
        active_managers = User.objects.filter(
            is_active=True,
            profile__role='Sales Manager',
            profile__is_approved=True
        ).order_by('username')
    else:
        # Sales Managers can only see agents and supervisors from their team
        if user_profile.role == 'Sales Manager':
            active_agents = User.objects.filter(
                is_active=True,
                profile__role='Sales Agent',
                profile__team=user_profile.team,
                profile__is_approved=True
            ).order_by('username')
            active_supervisors = User.objects.filter(
                is_active=True,
                profile__role='Sales Supervisor',
                profile__team=user_profile.team,
                profile__is_approved=True
            ).order_by('username')
            active_managers = User.objects.filter(
                is_active=True,
                profile__role='Sales Manager',
                profile__team=user_profile.team,
                profile__is_approved=True
            ).order_by('username')
        else:
            messages.error(request, "You don't have permission to create commission slips.")
            return redirect('commission_history')

    if request.method == 'POST':
        slip_form = CommissionSlipForm3(request.POST)
        if slip_form.is_valid():
            # Get form data
            sales_agent_name = request.POST.get('sales_agent_name')
            supervisor_name = request.POST.get('supervisor_name')
            manager_name = request.POST.get('manager_name')
            buyer_name = request.POST.get('buyer_name')
            project_name = request.POST.get('project_name')
            unit_id = request.POST.get('unit_id')
            total_selling_price = Decimal(request.POST.get('total_selling_price', 0))
            cash_advance = Decimal(request.POST.get('cash_advance', 0))
            particulars = request.POST.get('particulars[]', 'FULL COMM')
            partial_percentage = Decimal(request.POST.get('partial_percentage', '100'))

            # Get separate tax rates for agent, supervisor and manager
            agent_tax_rate = Decimal(request.POST.get('withholding_tax_rate', 10.00))
            supervisor_tax_rate = Decimal(request.POST.get('supervisor_withholding_tax_rate', 10.00))
            manager_tax_rate = Decimal(request.POST.get('manager_tax_rate', 10.00))

            # Calculate cash advance tax (10%)
            cash_advance_tax = cash_advance * Decimal('0.10')
            net_cash_advance = cash_advance - cash_advance_tax

            # Calculate adjusted total
            adjusted_total = total_selling_price - net_cash_advance

            # Create commission slip
            slip = CommissionSlip3.objects.create(
                sales_agent_name=sales_agent_name,
                supervisor_name=supervisor_name,
                manager_name=manager_name,
                buyer_name=buyer_name,
                project_name=project_name,
                unit_id=unit_id,
                total_selling_price=total_selling_price,
                cash_advance=cash_advance,
                cash_advance_tax=cash_advance_tax,
                incentive_amount=Decimal(request.POST.get('incentive_amount', 0)),
                date=request.POST.get('date'),
                created_by=request.user,
                created_at=timezone.now(),
                withholding_tax_rate=agent_tax_rate,
                supervisor_withholding_tax_rate=supervisor_tax_rate,
                manager_tax_rate=manager_tax_rate,
                source='manual_breakdown'  # Set the source
            )
                    
            # Get commission rates for agent, supervisor and manager
            agent_commission_rate = Decimal(request.POST.get('agent_commission_rate', 0))
            supervisor_commission_rate = Decimal(request.POST.get('supervisor_commission_rate', 0))
            manager_commission_rate = Decimal(request.POST.get('manager_commission_rate', 0))

            # Create commission details for agent
            if agent_commission_rate > 0:
                # Calculate base commission
                base_commission = adjusted_total * agent_commission_rate / 100

                # Apply partial percentage if applicable
                if particulars == 'PARTIAL COMM':
                    base_commission = base_commission * (partial_percentage / 100)

                # Calculate gross commission
                gross_commission = base_commission
                if particulars == 'INCENTIVES':
                    gross_commission = base_commission + Decimal(request.POST.get('incentive_amount', 0))

                # Calculate tax using agent tax rate
                tax_rate = agent_tax_rate / 100
                withholding_tax = gross_commission * tax_rate
                net_commission = gross_commission - withholding_tax

                # Create agent commission detail
                CommissionDetail3.objects.create(
                    slip=slip,
                    position='Sales Agent',
                    particulars=particulars,
                    commission_rate=agent_commission_rate,
                    base_commission=base_commission,
                    gross_commission=gross_commission,
                    withholding_tax=withholding_tax,
                    net_commission=net_commission,
                    agent_name=sales_agent_name,
                    partial_percentage=partial_percentage,
                    withholding_tax_rate=agent_tax_rate,
                    is_supervisor=False
                )

            # Create commission details for supervisor
            if supervisor_commission_rate > 0:
                # Calculate base commission
                base_commission = adjusted_total * supervisor_commission_rate / 100

                # Apply partial percentage if applicable
                if particulars == 'PARTIAL COMM':
                    base_commission = base_commission * (partial_percentage / 100)

                # Calculate gross commission
                gross_commission = base_commission
                if particulars == 'INCENTIVES':
                    gross_commission = base_commission + Decimal(request.POST.get('incentive_amount', 0))

                # Calculate tax using supervisor tax rate
                tax_rate = supervisor_tax_rate / 100
                withholding_tax = gross_commission * tax_rate
                net_commission = gross_commission - withholding_tax

                # Create supervisor commission detail
                CommissionDetail3.objects.create(
                    slip=slip,
                    position='Sales Supervisor',
                    particulars=particulars,
                    commission_rate=supervisor_commission_rate,
                    base_commission=base_commission,
                    gross_commission=gross_commission,
                    withholding_tax=withholding_tax,
                    net_commission=net_commission,
                    agent_name=supervisor_name,
                    partial_percentage=partial_percentage,
                    withholding_tax_rate=supervisor_tax_rate,
                    is_supervisor=True
                )

            # Create commission details for manager
            if manager_commission_rate > 0:
                # Calculate base commission
                base_commission = adjusted_total * manager_commission_rate / 100

                # Apply partial percentage if applicable
                if particulars == 'PARTIAL COMM':
                    base_commission = base_commission * (partial_percentage / 100)

                # Calculate gross commission
                gross_commission = base_commission
                if particulars == 'INCENTIVES':
                    gross_commission = base_commission + Decimal(request.POST.get('incentive_amount', 0))

                # Calculate tax using manager tax rate
                tax_rate = manager_tax_rate / 100
                withholding_tax = gross_commission * tax_rate
                net_commission = gross_commission - withholding_tax

                # Create manager commission detail
                CommissionDetail3.objects.create(
                    slip=slip,
                    position='Sales Manager',
                    particulars=particulars,
                    commission_rate=manager_commission_rate,
                    base_commission=base_commission,
                    gross_commission=gross_commission,
                    withholding_tax=withholding_tax,
                    net_commission=net_commission,
                    agent_name=manager_name,
                    partial_percentage=partial_percentage,
                    withholding_tax_rate=manager_tax_rate,
                    is_supervisor=False
                )

            messages.success(request, "Commission slip created successfully!")
            return redirect('commission_history')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        slip_form = CommissionSlipForm3()
    properties = Property.objects.all().order_by('name')

    return render(request, 'create_commission_slip3.html', {
        'slip_form': slip_form,
        'active_agents': active_agents,
        'active_supervisors': active_supervisors,
        'active_managers': active_managers,
        'user_role': user_profile.role,
        'properties': properties
    })

@login_required(login_url='signin')
def commission3(request, slip_id):
    # Get the commission slip
    slip = get_object_or_404(CommissionSlip3, id=slip_id)
    
    # Check if user has permission to view this slip
    can_view = (
        request.user.is_superuser or
        request.user.is_staff or
        slip.created_by == request.user or
        slip.sales_agent_name == request.user.get_full_name() or
        slip.supervisor_name == request.user.get_full_name() or
        slip.manager_name == request.user.get_full_name() or
        (request.user.profile.role == 'Sales Manager' and 
         hasattr(request.user, 'profile') and 
         hasattr(request.user.profile, 'team'))
    )

    if not can_view:
        messages.error(request, 'You do not have permission to view this commission slip.')
        return redirect('commission_history')
    
    # Get all commission details
    details = CommissionDetail3.objects.filter(slip=slip)
    
    # Recalculate withholding tax and net commission for each detail using appropriate tax rate
    for detail in details:
        if detail.agent_name == slip.sales_agent_name:
            # Use agent tax rate
            tax_rate = slip.withholding_tax_rate / 100
        elif detail.agent_name == slip.supervisor_name:
            # Use supervisor tax rate
            tax_rate = slip.supervisor_withholding_tax_rate / 100
        else:
            # Use manager tax rate
            tax_rate = slip.manager_tax_rate / 100
            
        # Recalculate withholding tax and net commission
        detail.withholding_tax = detail.gross_commission * tax_rate
        detail.net_commission = detail.gross_commission - detail.withholding_tax
        detail.save()
    
    # Filter details based on user role and permissions first
    user_role = request.user.profile.role
    user_name = request.user.get_full_name()
    
    if request.user.is_superuser or request.user.is_staff:
        # Staff and superusers can see all details
        filtered_details = details
    elif user_role == 'Sales Manager':
        # Sales Managers can see all details to view supervisor/agent breakdowns
        filtered_details = details
    elif user_role == 'Sales Supervisor' and user_name == slip.supervisor_name:
        # Supervisor can see both their own and their agent's details, but not manager details
        filtered_details = details.filter(
            Q(agent_name=slip.sales_agent_name) | Q(agent_name=user_name)
        )
    elif user_role == 'Sales Agent' and user_name == slip.sales_agent_name:
        # Agent can only see their own details
        filtered_details = details.filter(agent_name=user_name)
    else:
        # For other cases, show only their own details
        filtered_details = details.filter(agent_name=user_name)
    
    # Calculate totals based on filtered details (what the user can see)
    total_gross = sum(detail.gross_commission for detail in filtered_details)
    total_tax = sum(detail.withholding_tax for detail in filtered_details)
    total_net = sum(detail.net_commission for detail in filtered_details)
    
    return render(request, 'commission3.html', {
        'slip': slip,
        'details': filtered_details,
        'total_gross': total_gross,
        'total_tax': total_tax,
        'total_net': total_net,
        'user_role': user_role,
        'is_staff': request.user.is_staff,
        'is_superuser': request.user.is_superuser,
        'is_creator': slip.created_by == request.user
    })

@login_required(login_url='signin')
def delete_tranche(request, tranche_id):
    # Get the tranche record
    tranche = get_object_or_404(TrancheRecord, id=tranche_id)
    
    # Check if user has permission to delete
    if not (request.user.is_superuser or request.user.is_staff or request.user == tranche.created_by):
        messages.error(request, 'You do not have permission to delete this tranche record.')
        return redirect('tranche_history')
    
    if request.method == 'POST':
        try:
            # Delete associated payments first
            tranche.payments.all().delete()
            
            # Delete associated commission records using the tranche ID
            # This is more reliable than matching by project and buyer names.
            tranche_id_str = str(tranche.id)
            Commission.objects.filter(
                Q(release_number__startswith=f'DP-{tranche_id_str}') | 
                Q(release_number__startswith=f'LTO-{tranche_id_str}')
            ).delete()
            
            # Delete the tranche record
            tranche.delete()
            messages.success(request, 'Tranche record deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting tranche record: {str(e)}')
    
    return redirect('tranche_history')

@login_required
def add_property(request):
    if not (request.user.is_superuser or request.user.is_staff):
        messages.error(request, 'You do not have permission to manage properties.')
        return redirect('home')
        
    if request.method == 'POST':
        name = request.POST.get('name')
        developer_id = request.POST.get('developer')
        image = request.FILES.get('image')
        developer_obj = Developer.objects.filter(id=developer_id).first() if developer_id else None
        
        if name:
            try:
                property = Property.objects.create(name=name, developer=developer_obj, image=image)
                messages.success(request, f'Property "{property.name}" added successfully!')
                return redirect('add_property')
            except Exception as e:
                messages.error(request, f'Error adding property: {str(e)}')
        else:
            messages.error(request, 'Property name is required.')
    
    # Get all developers for the dropdown
    developers = Developer.objects.all().order_by('name')
    properties = Property.objects.all().order_by('name')
    
    context = {
        'developers': developers,
        'properties': properties,
    }
    return render(request, 'add_property.html', context)

@login_required
def add_developer(request):
    if not (request.user.is_superuser or request.user.is_staff):
        messages.error(request, 'You do not have permission to manage developers.')
        return redirect('home')
        
    if request.method == 'POST':
        name = request.POST.get('name')
        address = request.POST.get('address')
        tin_number = request.POST.get('tin_number')
        image = request.FILES.get('image')
        
        if name:
            developer = Developer.objects.create(
                name=name,
                address=address,
                tin_number=tin_number,
                image=image
            )
            return redirect('add_developer')
    
    # Get all developers for display
    developers = Developer.objects.all().order_by('name')
    
    context = {
        'developers': developers,
    }
    return render(request, 'add_developer.html', context)

@login_required
@require_http_methods(["POST"])
def edit_developer(request, developer_id):
    if not (request.user.is_superuser or request.user.is_staff):
        return JsonResponse({'success': False, 'error': 'Permission denied'})
    
    try:
        developer = Developer.objects.get(id=developer_id)
        
        # Update fields
        developer.name = request.POST.get('name', developer.name)
        developer.address = request.POST.get('address', developer.address)
        developer.tin_number = request.POST.get('tin_number', developer.tin_number)
        
        # Handle image upload
        if 'image' in request.FILES:
            developer.image = request.FILES['image']
        
        developer.save()
        
        return JsonResponse({'success': True})
    except Developer.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Developer not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["POST"])
def edit_property(request, property_id):
    if not (request.user.is_superuser or request.user.is_staff):
        return JsonResponse({'success': False, 'error': 'Permission denied'})
    
    try:
        property_obj = Property.objects.get(id=property_id)
        
        # Update fields
        property_obj.name = request.POST.get('name', property_obj.name)
        
        # Handle developer assignment
        developer_id = request.POST.get('developer')
        if developer_id:
            try:
                developer = Developer.objects.get(id=developer_id)
                property_obj.developer = developer
            except Developer.DoesNotExist:
                property_obj.developer = None
        else:
            property_obj.developer = None
        
        # Handle image upload
        if 'image' in request.FILES:
            property_obj.image = request.FILES['image']
        
        property_obj.save()
        
        return JsonResponse({'success': True})
    except Property.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Property not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def delete_property(request, property_id):
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': 'Only superusers can delete properties.'
        }, status=403)
    
    try:
        property = get_object_or_404(Property, id=property_id)
        property.delete()
        return JsonResponse({
            'status': 'success',
            'message': 'Property deleted successfully!'
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=400)

@login_required
def delete_developer(request, developer_id):
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': 'Only superusers can delete developers.'
        }, status=403)
    
    try:
        developer = get_object_or_404(Developer, id=developer_id)
        developer.delete()
        return JsonResponse({
            'status': 'success',
            'message': 'Developer deleted successfully!'
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=400)

def is_superuser(user):
    return user.is_superuser

@user_passes_test(is_superuser)
def manage_teams(request):
    teams = Team.objects.all().order_by('name')
    return render(request, 'manage_teams.html', {'teams': teams})

@user_passes_test(is_superuser)
def add_team(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        display_name = request.POST.get('display_name')
        
        if not name or not display_name:
            return JsonResponse({
                'status': 'error',
                'message': 'Both name and display name are required.'
            })
            
        try:
            team = Team.objects.create(
                name=name,
                display_name=display_name
            )
            return JsonResponse({
                'status': 'success',
                'message': f'Team {display_name} created successfully.'
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })
    
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method.'
    })

@user_passes_test(is_superuser)
def delete_team(request, team_id):
    if request.method == 'DELETE':
        team = get_object_or_404(Team, id=team_id)
        try:
            team.delete()
            return JsonResponse({
                'status': 'success',
                'message': f'Team {team.display_name} deleted successfully.'
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })
    
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method.'
    })


@login_required(login_url='signin')
def create_commission_slip3(request):
    if not request.user.is_active:
        messages.error(request, "Your account is not active.")
        return redirect('signin')

    # Get the current user's profile
    user_profile = request.user.profile

    # Filter users based on role and permissions
    if request.user.is_superuser or request.user.is_staff:
        # Superusers and staff can see all active agents and supervisors from all teams
        active_agents = User.objects.filter(
            is_active=True,
            profile__role='Sales Agent',
            profile__is_approved=True
        ).order_by('username')
        active_supervisors = User.objects.filter(
            is_active=True,
            profile__role='Sales Supervisor',
            profile__is_approved=True
        ).order_by('username')
        active_managers = User.objects.filter(
            is_active=True,
            profile__role='Sales Manager',
            profile__is_approved=True
        ).order_by('username')
    else:
        # Sales Managers can only see agents and supervisors from their team
        if user_profile.role == 'Sales Manager':
            active_agents = User.objects.filter(
                is_active=True,
                profile__role='Sales Agent',
                profile__team=user_profile.team,
                profile__is_approved=True
            ).order_by('username')
            active_supervisors = User.objects.filter(
                is_active=True,
                profile__role='Sales Supervisor',
                profile__team=user_profile.team,
                profile__is_approved=True
            ).order_by('username')
            active_managers = User.objects.filter(
                is_active=True,
                profile__role='Sales Manager',
                profile__team=user_profile.team,
                profile__is_approved=True
            ).order_by('username')
        else:
            messages.error(request, "You don't have permission to create commission slips.")
            return redirect('commission_history')

    if request.method == 'POST':
        slip_form = CommissionSlipForm3(request.POST)
        if slip_form.is_valid():
            # Get form data
            sales_agent_name = request.POST.get('sales_agent_name')
            supervisor_name = request.POST.get('supervisor_name')
            manager_id = request.POST.get('manager_id')
            if manager_id:
                manager_user = User.objects.filter(id=manager_id).first()
                manager_name = manager_user.get_full_name() if manager_user else ''
            else:
                # Fallback to the readonly input value if provided
                manager_name = request.POST.get('sales_manager_name', '')
            buyer_name = request.POST.get('buyer_name')
            project_name = request.POST.get('project_name')
            unit_id = request.POST.get('unit_id')
            total_selling_price = Decimal(request.POST.get('total_selling_price', 0))
            cash_advance = Decimal(request.POST.get('cash_advance', 0))
            particulars = request.POST.get('particulars[]', 'FULL COMM')
            partial_percentage = Decimal(request.POST.get('partial_percentage', '100'))

            # Get separate tax rates for agent, supervisor and manager
            agent_tax_rate = Decimal(request.POST.get('withholding_tax_rate', 10.00))
            supervisor_tax_rate = Decimal(request.POST.get('supervisor_withholding_tax_rate', 10.00))
            manager_tax_rate = Decimal(request.POST.get('manager_tax_rate', 10.00))

            # Calculate cash advance tax (10%)
            cash_advance_tax = cash_advance * Decimal('0.10')
            net_cash_advance = cash_advance - cash_advance_tax

            # Calculate adjusted total
            adjusted_total = total_selling_price - net_cash_advance

            # Create commission slip
            slip = CommissionSlip3.objects.create(
                sales_agent_name=sales_agent_name,
                supervisor_name=supervisor_name,
                manager_name=manager_name,
                buyer_name=buyer_name,
                project_name=project_name,
                unit_id=unit_id,
                total_selling_price=total_selling_price,
                cash_advance=cash_advance,
                cash_advance_tax=cash_advance_tax,
                incentive_amount=Decimal(request.POST.get('incentive_amount', 0)),
                date=request.POST.get('date'),
                created_by=request.user,
                created_at=timezone.now(),
                withholding_tax_rate=agent_tax_rate,
                supervisor_withholding_tax_rate=supervisor_tax_rate,
                manager_tax_rate=manager_tax_rate,
                source='manual_breakdown'  # Set the source
            )
                    
            # Get commission rates for agent, supervisor and manager
            agent_commission_rate = Decimal(request.POST.get('agent_commission_rate', 0))
            supervisor_commission_rate = Decimal(request.POST.get('supervisor_commission_rate', 0))
            manager_commission_rate = Decimal(request.POST.get('manager_commission_rate', 0))

            # Create commission details for agent
            if agent_commission_rate > 0:
                # Calculate base commission
                base_commission = adjusted_total * agent_commission_rate / 100

                # Apply partial percentage if applicable
                if particulars == 'PARTIAL COMM':
                    base_commission = base_commission * (partial_percentage / 100)

                # Calculate gross commission
                gross_commission = base_commission
                if particulars == 'INCENTIVES':
                    gross_commission = base_commission + Decimal(request.POST.get('incentive_amount', 0))

                # Calculate tax using agent tax rate
                tax_rate = agent_tax_rate / 100
                withholding_tax = gross_commission * tax_rate
                net_commission = gross_commission - withholding_tax

                # Create agent commission detail
                CommissionDetail3.objects.create(
                    slip=slip,
                    position='Sales Agent',
                    particulars=particulars,
                    commission_rate=agent_commission_rate,
                    base_commission=base_commission,
                    gross_commission=gross_commission,
                    withholding_tax=withholding_tax,
                    net_commission=net_commission,
                    agent_name=sales_agent_name,
                    partial_percentage=partial_percentage,
                    withholding_tax_rate=agent_tax_rate,
                    is_supervisor=False
                )

            # Create commission details for supervisor
            if supervisor_commission_rate > 0:
                # Calculate base commission
                base_commission = adjusted_total * supervisor_commission_rate / 100

                # Apply partial percentage if applicable
                if particulars == 'PARTIAL COMM':
                    base_commission = base_commission * (partial_percentage / 100)

                # Calculate gross commission
                gross_commission = base_commission
                if particulars == 'INCENTIVES':
                    gross_commission = base_commission + Decimal(request.POST.get('incentive_amount', 0))

                # Calculate tax using supervisor tax rate
                tax_rate = supervisor_tax_rate / 100
                withholding_tax = gross_commission * tax_rate
                net_commission = gross_commission - withholding_tax

                # Create supervisor commission detail
                CommissionDetail3.objects.create(
                    slip=slip,
                    position='Sales Supervisor',
                    particulars=particulars,
                    commission_rate=supervisor_commission_rate,
                    base_commission=base_commission,
                    gross_commission=gross_commission,
                    withholding_tax=withholding_tax,
                    net_commission=net_commission,
                    agent_name=supervisor_name,
                    partial_percentage=partial_percentage,
                    withholding_tax_rate=supervisor_tax_rate,
                    is_supervisor=True
                )

            # Create commission details for manager
            if manager_commission_rate > 0:
                # Calculate base commission
                base_commission = adjusted_total * manager_commission_rate / 100

                # Apply partial percentage if applicable
                if particulars == 'PARTIAL COMM':
                    base_commission = base_commission * (partial_percentage / 100)

                # Calculate gross commission
                gross_commission = base_commission
                if particulars == 'INCENTIVES':
                    gross_commission = base_commission + Decimal(request.POST.get('incentive_amount', 0))

                # Calculate tax using manager tax rate
                tax_rate = manager_tax_rate / 100
                withholding_tax = gross_commission * tax_rate
                net_commission = gross_commission - withholding_tax

                # Create manager commission detail
                CommissionDetail3.objects.create(
                    slip=slip,
                    position='Sales Manager',
                    particulars=particulars,
                    commission_rate=manager_commission_rate,
                    base_commission=base_commission,
                    gross_commission=gross_commission,
                    withholding_tax=withholding_tax,
                    net_commission=net_commission,
                    agent_name=manager_name,
                    partial_percentage=partial_percentage,
                    withholding_tax_rate=manager_tax_rate,
                    is_supervisor=False
                )

            messages.success(request, "Commission slip created successfully!")
            return redirect('commission_history')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        slip_form = CommissionSlipForm3()
    properties = Property.objects.all().order_by('name')

    return render(request, 'create_commission_slip3.html', {
        'slip_form': slip_form,
        'active_agents': active_agents,
        'active_supervisors': active_supervisors,
        'active_managers': active_managers,
        'user_role': user_profile.role,
        'properties': properties
    })
