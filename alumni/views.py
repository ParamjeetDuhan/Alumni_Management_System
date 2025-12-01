import re, random, pandas as pd
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email, URLValidator
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from .models import Alumni, Event, Job, News, User
from .forms import EventForm, JobForm, NewsForm, AlumniImportForm, CustomPasswordChangeForm


# Home Page
@csrf_exempt
def home(request):
    return render(request, 'index.html')

def get_stats(request):
    alumni_count = Alumni.objects.count()
    companies = Alumni.objects.values('company').exclude(company="").distinct().count()
    events = Event.objects.count()
    jobs = Job.objects.count()
    
    return JsonResponse({
        'alumniCount': alumni_count,
        'companies': companies,
        'events': events,
        'jobs': jobs
    })

# Alumni Registration
@csrf_exempt
def register(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        gender = request.POST.get('gender', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        roll_no = request.POST.get('roll_no', '').strip() 
        graduation_year = request.POST.get('graduation_year')
        major = request.POST.get('major', '').strip()
        phone = request.POST.get('phone', '').strip()
        location = request.POST.get('location', '').strip()
        current_position = request.POST.get('current_position', '').strip()
        company = request.POST.get('company', '').strip()
        bio = request.POST.get('bio', '').strip()

        # Validate passwords
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('register')

        # Check if email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists.')
            return redirect('register')

        # Check for existing phone or roll number
        if Alumni.objects.filter(phone=phone).exists():
            messages.error(request, 'Phone number already exists.')
            return redirect('register')

        if Alumni.objects.filter(roll_no=roll_no).exists():  
            messages.error(request, 'Roll number already exists.')
            return redirect('register')

        # Create the user
        user = User.objects.create_user(
            username=roll_no,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )

        # Create the alumni profile
        Alumni.objects.create(
            user=user,
            roll_no=roll_no, 
            graduation_year=graduation_year,
            major=major,
            phone=phone,
            location=location,
            current_position=current_position,
            company=company,
            bio=bio,
            gender=gender,
        )

        messages.success(request, 'Registration successful! Please wait for admin approval.')
        return redirect('login')

    return render(request, 'register.html')

# User Login (Common for both Alumni and Admin)
@csrf_exempt
def user_login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = authenticate(request, username=email, password=password)  # Pass email as username
        
        if user is not None:
            if user.role == 'alumni':
                if not user.approval_status:
                    messages.info(request, 'Your alumni account is awaiting admin approval.')
                    return redirect('login')
                else:
                    login(request, user)
                    return redirect('dashboard_alumni')  # Redirect alumni to their dashboard
            elif user.role in ['superadmin', 'eventmanager', 'contentmanager']:  # Admin roles
                login(request, user)
                return redirect('dashboard_admin')  # Redirect admin to their dashboard
        else:
            messages.error(request, 'Invalid email or password.')
    
    return render(request, 'login.html')

# User Logout
@csrf_exempt
@login_required
def user_logout(request):
    logout(request)
    return redirect('home')

#forgot password
@csrf_exempt
def forgot_password(request):
    step = request.POST.get('step', 'email')  # Default step is 'email'
    context = {'step': step}

    if request.method == 'POST':
        # Step 1: Send OTP to email
        if step == 'send_otp':
            email = request.POST.get('email')
            context['email'] = email
            try:
                user = User.objects.get(email=email)  # Try fetching the user by email
                otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP

                # Store OTP & email in session
                request.session['reset_email'] = email
                request.session['reset_otp'] = otp

                # Send OTP to email
                send_mail(
                    subject="Your OTP for Password Reset",
                    message=f"Hello {user.first_name},\n\nYour OTP for password reset is: {otp}",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False
                )

                messages.success(request, 'OTP has been sent to your email.')
                context['step'] = 'otp'  # Proceed to OTP input page
            except User.DoesNotExist:
                messages.error(request, 'Email not registered.')
                context['step'] = 'email'

        # Step 2: Verify OTP
        elif step == 'verify_otp':
            otp_input = request.POST.get('otp')  # OTP entered by the user
            stored_otp = request.session.get('reset_otp')  # OTP stored in session

            if otp_input == stored_otp:
                messages.success(request, 'OTP verified successfully. You can now reset your password.')
                context['step'] = 'reset'  # Proceed to reset password step
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
                context['step'] = 'otp'  # Stay on OTP input step

        # Step 3: Reset password
        elif step == 'reset_password':
            password = request.POST.get('password')
            confirm = request.POST.get('confirm')
            email = request.session.get('reset_email')

            # Ensure passwords match
            if password != confirm:
                messages.error(request, 'Passwords do not match.')
                context['step'] = 'reset'
            elif not is_strong_password(password):
                messages.error(request, 'Password must be at least 8 characters long, contain one uppercase letter, one number, and one special character.')
                context['step'] = 'reset'
            else:
                try:
                    user = User.objects.get(email=email)
                    user.password = make_password(password)  # Hash the new password
                    user.save()

                    # Clear session data (OTP and email)
                    request.session.pop('reset_email', None)
                    request.session.pop('reset_otp', None)

                    messages.success(request, 'Password reset successfully. You can now log in.')
                    return redirect('login')  # Redirect to login page after successful reset
                except User.DoesNotExist:
                    messages.error(request, 'Something went wrong. Please try again.')

        # Step 2: Resend OTP
        elif step == 'resend_otp':
            email = request.session.get('reset_email')  # Get email from session
            otp = request.session.get('reset_otp')  # OTP from session
            if email and otp:
                try:
                    user = User.objects.get(email=email)  # Try fetching the user by email
                    # Resend OTP
                    send_mail(
                        subject="Your OTP for Password Reset",
                        message=f"Hello {user.first_name},\n\nYour OTP for password reset is: {otp}",
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        fail_silently=False
                    )

                    messages.success(request, 'OTP has been resent to your email.')
                except User.DoesNotExist:
                    messages.error(request, 'Email not registered.')

                context['step'] = 'otp'  # Stay on OTP input step

    return render(request, 'forgot_password.html', context)

# Function to check if the password is strong enough
def is_strong_password(password):
    # Regular expression to check password strength
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$'
    return re.match(pattern, password)

#Profile pic and Profile views by alumni
@login_required
@csrf_exempt
def upload_profile_picture(request):
    if request.method == 'POST' and request.FILES.get('profile_picture'):
        alumni = get_object_or_404(Alumni, user=request.user)
        alumni.profile_picture = request.FILES['profile_picture']
        alumni.save()
        messages.success(request, "Profile picture updated.")
    return redirect('my_profile')

#Send Message
def send_message(request, alumni_id):
    # Fetch the alumni whose profile is being viewed
    recipient = get_object_or_404(Alumni, id=alumni_id)
    
    # Handle sending the message (you can extend this as needed)
    if request.method == 'POST':
        message_content = request.POST.get('message')
        # Save the message to the database (implement this logic)
        # For now, we’ll just return a simple response.
        
        # Assuming you have a Message model to save the message:
        # Message.objects.create(sender=request.user, recipient=recipient, content=message_content)

        return HttpResponse("Message sent successfully to {}".format(recipient.user.get_full_name()))

    return render(request, 'send_message.html', {'recipient': recipient})

@login_required
@csrf_exempt
def view_alumni_profile(request, alumni_id):
    # Get the alumni instance
    alumni = get_object_or_404(Alumni, id=alumni_id)

    # Get the jobs and events associated with this alumni
    jobs = Job.objects.filter(posted_by=alumni.user)
    events = Event.objects.filter(created_by=alumni.user)

    # Count using the already fetched querysets
    job_count = jobs.count()
    event_count = events.count()

    # Render the profile page
    return render(request, 'view_alumni_profile.html', {
        'alumni': alumni,
        'jobs': jobs,
        'events': events,
        'job_count': job_count,
        'event_count': event_count,
    })

@login_required
@csrf_exempt
def view_alumni_profiles(request, alumni_id):
    # Get the alumni instance
    alumni = get_object_or_404(Alumni, id=alumni_id)

    # Get the jobs and events associated with this alumni
    jobs = Job.objects.filter(posted_by=alumni.user)
    events = Event.objects.filter(created_by=alumni.user)

    # Count using the already fetched querysets
    job_count = jobs.count()
    event_count = events.count()

    # Render the profile page
    return render(request, 'view_alumni_profiles.html', {
        'alumni': alumni,
        'jobs': jobs,
        'events': events,
        'job_count': job_count,
        'event_count': event_count,
    })

# Alumni Dashboard
@csrf_exempt
@login_required
def dashboard_alumni(request):
    if request.user.role == 'alumni':  # Ensure only alumni can access
        user_jobs = Job.objects.filter(posted_by=request.user)
        user_events = Event.objects.filter(created_by=request.user)
        news_list = News.objects.all()
        return render(request, 'dashboard_alumni.html', {
            'user_jobs': user_jobs,
            'user_events': user_events,
            'news_list': news_list,
        })
    return redirect('dashboard_admin')  # If not alumni, redirect to admin dashboard

# Admin Dashboard
@csrf_exempt
@login_required
def dashboard_admin(request):
    if request.user.role in ['superadmin', 'eventmanager', 'contentmanager']:  # Ensure only admins can access
        pending_alumni = Alumni.objects.filter(user__approval_status=False)
        job_list = Job.objects.all()
        event_list = Event.objects.all()
        news_list = News.objects.all()
        return render(request, 'dashboard_admin.html', {
            'pending_alumni': pending_alumni,
            'job_list': job_list,
            'event_list': event_list,
            'news_list': news_list,
        })
    return redirect('dashboard_alumni')  # If not admin, redirect to alumni dashboard

#ALumni list
@login_required
@csrf_exempt
def view_alumni_list(request):
    # Check user role (assuming you have a custom user model with a `role` attribute)
    if hasattr(request.user, 'role') and request.user.role in ['superadmin', 'eventmanager']:
        alumni_list = Alumni.objects.all()  # Retrieve all alumni records
        context = {
            'alumni_list': alumni_list,
        }
        return render(request, 'alumni_list.html', context)
    else:
        return redirect('dashboard_admin')
    
#Editalbe alumni details by admin
@login_required
@csrf_exempt
@require_POST
def update_alumni_field(request):
    if request.method == 'POST':
        try:
            alumni_id = request.POST.get('id')
            field = request.POST.get('field')
            value = request.POST.get('value')

            alumni = Alumni.objects.get(pk=alumni_id)
            user = alumni.user

            if field == 'name':
                name_parts = value.split(' ', 1)
                first_name = name_parts[0]
                last_name = name_parts[1] if len(name_parts) > 1 else ''
                user.first_name = first_name
                user.last_name = last_name
                user.save()

            elif field == 'email':
                if User.objects.exclude(pk=user.pk).filter(email=value).exists():
                    return JsonResponse({'success': False, 'error': 'Email already exists'})
                user.email = value
                user.save()

            elif field == 'roll_no':
                if Alumni.objects.exclude(pk=alumni.pk).filter(roll_no=value).exists():
                    return JsonResponse({'success': False, 'error': 'Roll number already exists'})
                alumni.roll_no = value
                alumni.save()

            elif field == 'graduation_year':
                try:
                    alumni.graduation_year = int(value)
                    alumni.save()
                except ValueError:
                    return JsonResponse({'success': False, 'error': 'Invalid graduation year'})
                
            elif field == 'gender':
                if value not in ['Male', 'Female', 'Other']:
                    return JsonResponse({'success': False, 'error': 'Invalid gender value'})
                alumni.gender = value
                alumni.save()

            elif field in ['major', 'phone', 'location', 'current_position', 'company']:
                setattr(alumni, field, value)
                alumni.save()

            else:
                return JsonResponse({'success': False, 'error': 'Invalid field'})

            return JsonResponse({'success': True})

        except Alumni.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Alumni not found'})

        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request'})
    
@login_required
@csrf_exempt
def remove_alumni(request, alumni_id):
    # Check if the user has the necessary role (superadmin or eventmanager)
    if hasattr(request.user, 'role') and request.user.role in ['superadmin', 'eventmanager']:
        try:
            # Get the Alumni object or return a 404 if not found
            alumni = get_object_or_404(Alumni, id=alumni_id)
            
            # Delete the related user to remove both Alumni and their User record
            alumni.user.delete()
            
            # Send a success message to the user
            messages.success(request, 'Alumni removed successfully.')
        except Exception as e:
            # If any error occurs, return an error message
            messages.error(request, f'Error removing alumni: {str(e)}')
    else:
        # If the user doesn't have permission, show an error message
        messages.error(request, 'You do not have permission to remove alumni.')

    # Redirect the user to the alumni list page
    return redirect('view_alumni_list')
@login_required
@csrf_exempt
@require_POST
def bulk_remove_alumni(request):
    if hasattr(request.user, 'role') and request.user.role in ['superadmin', 'eventmanager']:
        selected = request.POST.getlist('selected_alumni')
        
        # Some browsers might send a single comma-separated string instead of real list
        ids = []
        for item in selected:
            ids.extend(item.split(','))  # split in case it's "30,31,33" in one item

        ids = [id.strip() for id in ids if id.strip().isdigit()]  # Keep only numbers

        not_found = []
        removed_count = 0

        for alumni_id in ids:
            try:
                alumni = Alumni.objects.get(id=int(alumni_id))
                if alumni.user:
                    alumni.user.delete()
                alumni.delete()  # delete Alumni even if user was missing
                removed_count += 1
            except Alumni.DoesNotExist:
                not_found.append(alumni_id)

        if not_found:
            messages.warning(request, f'Some alumni were not found or invalid: {", ".join(not_found)}')
        if removed_count > 0:
            messages.success(request, f'{removed_count} alumni removed successfully.')
    else:
        messages.error(request, 'Permission denied.')

    return redirect('view_alumni_list')

#Admin update profile picture
@login_required
@csrf_exempt
def admin_update_profile_picture(request, user_id):
    if request.user.role not in ['superadmin', 'eventmanager']:
        messages.error(request, "You don't have permission to perform this action.")
        return redirect('dashboard_admin')

    alumni = get_object_or_404(Alumni, user__id=user_id)

    if request.method == 'POST' and request.FILES.get('profile_picture'):
        alumni.profile_picture = request.FILES['profile_picture']
        alumni.save()
        messages.success(request, "Profile picture updated successfully.")
    else:
        messages.error(request, "No profile picture was uploaded.")

    return redirect('view_alumni_profiles', alumni_id=alumni.id)

# Approve Alumni (Super Admin Only)
@csrf_exempt
@login_required
def approve_alumni(request, alumni_id):
    if request.user.role in ['superadmin', 'eventmanager']:
        alumni = get_object_or_404(Alumni, user_id=alumni_id)
        alumni.user.approval_status = True
        alumni.user.save()
        messages.success(request, 'Alumni approved successfully!')
    else:
        messages.error(request, 'You do not have permission to approve alumni.')
    return redirect('dashboard_admin')

# Decline Alumni (Super Admin Only)
@csrf_exempt
@login_required
def decline_alumni(request, alumni_id):
    if request.user.role in ['superadmin', 'eventmanager']:
        alumni = get_object_or_404(Alumni, user_id=alumni_id)
        alumni.user.delete()  # Delete both the user and alumni
        messages.success(request, 'Alumni declined and removed from the list.')
    else:
        messages.error(request, 'You do not have permission to decline alumni.')
    return redirect('dashboard_admin')

# Post Event (Alumni Only)
@csrf_exempt
@login_required
def post_event(request):
    if request.user.role == 'alumni':  # Ensure only alumni can post events
        if request.method == 'POST':
            form = EventForm(request.POST)
            if form.is_valid():
                event = form.save(commit=False)
                event.created_by = request.user
                event.save()
                messages.success(request, 'Event posted successfully!')
                return redirect('dashboard_alumni')
        else:
            form = EventForm()
        return render(request, 'post_event.html', {'form': form})
    return redirect('dashboard_admin')  # Redirect to admin dashboard if not alumni

# Post Job (Alumni Only)
@csrf_exempt
@login_required
def post_job(request):
    if request.user.role == 'alumni':  # Ensure only alumni can post jobs
        if request.method == 'POST':
            form = JobForm(request.POST)
            if form.is_valid():
                job = form.save(commit=False)
                job.posted_by = request.user
                job.save()
                messages.success(request, 'Job posted successfully!')
                return redirect('dashboard_alumni')
        else:
            form = JobForm()
        return render(request, 'post_job.html', {'form': form})
    return redirect('dashboard_admin')  # Redirect to admin dashboard if not alumni

# Post News (Admin Only)
@csrf_exempt
@login_required
def post_news(request):
    if request.user.role in ['superadmin', 'contentmanager']:  # Ensure only admins with proper role can post news
        if request.method == 'POST':
            form = NewsForm(request.POST)
            if form.is_valid():
                news = form.save(commit=False)
                news.created_by = request.user
                news.save()
                messages.success(request, 'News posted successfully!')
                return redirect('dashboard_admin')
        else:
            form = NewsForm()
        return render(request, 'post_news.html', {'form': form})
    messages.error(request, 'You do not have permission to post news.')
    return redirect('dashboard_admin')

# View All Events
@csrf_exempt
@login_required
def view_events(request):
    all_events = Event.objects.all()
    return render(request, 'view_events.html', {'all_events': all_events})

# View All Jobs
@login_required
@csrf_exempt
def view_jobs(request):
    all_jobs = Job.objects.all()
    return render(request, 'view_jobs.html', {'all_jobs': all_jobs})

#Alumni directory
@login_required
@csrf_exempt
def alumni_directory(request):
     # Get all other alumni for directory (excluding self)
    all_alumni = Alumni.objects.exclude(user=request.user)
    return render(request, 'alumni_directory.html', {'all_alumni': all_alumni})

# Profile management
@login_required
@csrf_exempt
def my_profile(request):
    # Get the current user's alumni profile
    alumni = get_object_or_404(Alumni, user=request.user)

    # Get all other alumni for directory (excluding self)
    all_alumni = Alumni.objects.exclude(user=request.user)

    job_count = Job.objects.filter(posted_by=request.user).count()
    event_count = Event.objects.filter(created_by=request.user).count()

    context = {
        'alumni': alumni,
        'all_alumni': all_alumni,
        'job_count': job_count,
        'event_count': event_count,
    }
    return render(request, 'my_profile.html', context)

#Inline profile edit
@login_required
@csrf_exempt
@require_POST
def update_profile_field(request):
    if not request.user.is_authenticated or request.method != "POST":
        return JsonResponse({'status': 'error', 'message': 'Unauthorized'}, status=403)

    field = request.POST.get('field')
    value = request.POST.get('value', '').strip()

    if not field:
        return JsonResponse({'status': 'error', 'message': 'No field specified'}, status=400)

    field = field.strip().lower()
    alumni = getattr(request.user, 'alumni', None)

    if not alumni:
        return JsonResponse({'status': 'error', 'message': 'Alumni profile not found'}, status=404)

    try:
        if field == 'gender':
            allowed_genders = {
                'male': 'Male',
                'female': 'Female',
                'other': 'Other',
                'prefer not to say': 'Prefer not to say'
            }
            normalized_key = value.lower()
            if normalized_key not in allowed_genders:
                return JsonResponse({'status': 'error', 'message': 'Invalid gender'}, status=400)
            alumni.gender = allowed_genders[normalized_key]

        elif field == 'email':
            try:
                validate_email(value)
            except ValidationError:
                return JsonResponse({'status': 'error', 'message': 'Invalid email'}, status=400)
            request.user.email = value
            request.user.save()

        elif field == 'graduation_year':
            if not value.isdigit() or not (1900 <= int(value) <= 2100):
                return JsonResponse({'status': 'error', 'message': 'Invalid graduation year'}, status=400)
            alumni.graduation_year = int(value)

        elif field == 'phone':
            if not re.match(r'^\+?\d{7,15}$', value):
                return JsonResponse({'status': 'error', 'message': 'Invalid phone number'}, status=400)
            alumni.phone = value

        elif field == 'first_name':
            request.user.first_name = value
            request.user.save()

        elif field == 'last_name':
            request.user.last_name = value
            request.user.save()

        elif field == 'roll_no':
            alumni.roll_no = value

        elif field == 'major':
            alumni.major = value

        elif field == 'location':
            alumni.location = value

        elif field == 'company':
            alumni.company = value

        elif field == 'current_position':
            alumni.current_position = value

        elif field == 'bio':
            alumni.bio = value

        # --- Social Links Handling ---
        elif field in ['linkedin', 'github', 'twitter', 'website', 'instagram', 'facebook']:
            if value:
                try:
                    validate_url = URLValidator()
                    validate_url(value)
                except ValidationError:
                    return JsonResponse({'status': 'error', 'message': f'Invalid URL for {field}'}, status=400)
            setattr(alumni, field, value)

        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid field'}, status=400)

        alumni.save()
        return JsonResponse({'status': 'success'})

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

#change password
@login_required
@csrf_exempt
def password_change(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            new_password = form.cleaned_data['new_password1']
            request.user.set_password(new_password)
            request.user.save()
            update_session_auth_hash(request, request.user)  # Keep user logged in
            messages.success(request, 'Your password has been changed successfully.')
            return redirect('my_profile')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomPasswordChangeForm(user=request.user)

    return render(request, 'password_change.html', {'form': form})

# Edit News (Super Admin or Content Manager)
@csrf_exempt
@login_required
def edit_news(request, news_id):
    if request.user.role not in ['superadmin', 'contentmanager']:
        messages.error(request, 'You do not have permission to edit news.')
        return redirect('dashboard_admin')

    news = get_object_or_404(News, pk=news_id)

    if request.method == 'POST':
        form = NewsForm(request.POST, instance=news)
        if form.is_valid():
            form.save()
            messages.success(request, 'News updated successfully!')
            return redirect('dashboard_admin')
    else:
        form = NewsForm(instance=news)

    return render(request, 'edit_news.html', {'form': form, 'news': news})

# Delete News (Super Admin or Content Manager)
@csrf_exempt
@login_required
def delete_news(request, news_id):
    if request.user.role not in ['superadmin', 'contentmanager']:
        messages.error(request, 'You do not have permission to delete news.')
        return redirect('dashboard_admin')

    news = get_object_or_404(News, id=news_id)
    news.delete()
    messages.success(request, 'News deleted successfully!')
    return redirect('dashboard_admin')

# Admin Edit Job (Super Admin or Content Manager)
@csrf_exempt
@login_required
def admin_edit_job(request, job_id):
    if request.user.role not in ['superadmin', 'contentmanager']:
        messages.error(request, 'You are not authorized to edit this job.')
        return redirect('dashboard_admin')
    
    job = get_object_or_404(Job, id=job_id)
    
    if request.method == 'POST':
        form = JobForm(request.POST, instance=job)
        if form.is_valid():
            form.save()
            messages.success(request, 'Job updated successfully!')
            return redirect('dashboard_admin')
    else:
        form = JobForm(instance=job)
    
    return render(request, 'edit_job.html', {'form': form, 'job': job})

# Admin Edit Event (Super Admin or Event Manager)
@csrf_exempt
@login_required
def admin_edit_event(request, event_id):
    if request.user.role not in ['superadmin', 'eventmanager']:
        messages.error(request, 'You are not authorized to edit this event.')
        return redirect('dashboard_admin')
    
    event = get_object_or_404(Event, id=event_id)
    
    if request.method == 'POST':
        form = EventForm(request.POST, instance=event)
        if form.is_valid():
            form.save()
            messages.success(request, 'Event updated successfully!')
            return redirect('dashboard_admin')
    else:
        form = EventForm(instance=event)
    
    return render(request, 'edit_event.html', {'form': form, 'event': event})

# Alumni Edit Own Job
@csrf_exempt
@login_required
def edit_own_job(request, job_id):
    job = get_object_or_404(Job, id=job_id, posted_by=request.user)
    
    if request.method == 'POST':
        form = JobForm(request.POST, instance=job)
        if form.is_valid():
            form.save()
            messages.success(request, 'Job updated successfully!')
            return redirect('dashboard_alumni')
    else:
        form = JobForm(instance=job)
    
    return render(request, 'edit_job.html', {'form': form, 'job': job})

# Alumni Edit Own Event
@csrf_exempt
@login_required
def edit_own_event(request, event_id):
    event = get_object_or_404(Event, id=event_id, created_by=request.user)
    
    if request.method == 'POST':
        form = EventForm(request.POST, instance=event)
        if form.is_valid():
            form.save()
            messages.success(request, 'Event updated successfully!')
            return redirect('dashboard_alumni')
    else:
        form = EventForm(instance=event)
    
    return render(request, 'edit_event.html', {'form': form, 'event': event})

# Delete Own Job
@csrf_exempt
@login_required
def delete_own_job(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    if job.posted_by != request.user:
        messages.error(request, 'You are not authorized to delete this job.')
        return redirect('dashboard_alumni')
    job.delete()
    messages.success(request, 'Job deleted successfully!')
    return redirect('dashboard_alumni')

# Delete Own Event
@csrf_exempt
@login_required
def delete_own_event(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    if event.created_by != request.user:
        messages.error(request, 'You are not authorized to delete this event.')
        return redirect('dashboard_alumni')
    event.delete()
    messages.success(request, 'Event deleted successfully!')
    return redirect('dashboard_alumni')

# Admin Delete Job
@csrf_exempt
@login_required
def admin_delete_job(request, job_id):
    if request.user.role not in ['superadmin', 'contentmanager']:
        messages.error(request, 'You do not have permission to delete jobs.')
        return redirect('dashboard_admin')
    
    job = get_object_or_404(Job, id=job_id)
    job.delete()
    
    messages.success(request, 'Job deleted successfully by admin.')
    return redirect('dashboard_admin')

# Admin Delete Event
@csrf_exempt
@login_required
def admin_delete_event(request, event_id):
    if request.user.role not in ['superadmin', 'eventmanager']:
        messages.error(request, 'You do not have permission to delete events.')
        return redirect('dashboard_admin')
    event = get_object_or_404(Event, id=event_id)
    event.delete()
    messages.success(request, 'Event deleted successfully by admin.')
    return redirect('dashboard_admin')

#Import alumni file
@csrf_exempt
@login_required
def import_alumni(request):
    if request.method == "POST":
        form = AlumniImportForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            try:
                # Determine file type
                if file.name.endswith('.csv'):
                    df = pd.read_csv(file)
                elif file.name.endswith('.xlsx'):
                    df = pd.read_excel(file)
                else:
                    messages.error(request, "Invalid file format. Please upload a CSV or Excel file.")
                    return redirect('view_alumni_list')  # Correct URL for redirect

                # Required columns
                required_columns = {'first_name', 'last_name', 'email', 'graduation_year', 'major', 'phone', 'location', 'current_position', 'company'}
                if not required_columns.issubset(df.columns):
                    messages.error(request, "Missing required columns in the file.")
                    return redirect('view_alumni_list')

                # Set a default password for all imported alumni
                default_password = 'Student$123'

                for _, row in df.iterrows():
                    user, created = User.objects.get_or_create(
                        email=row['email'],
                        defaults={
                            'first_name': row['first_name'],
                            'last_name': row['last_name'],
                            'username': row['roll_no'],  # Ensure unique username
                        }
                    )
                    
                    # Set the default password if the user is newly created
                    if created:
                        user.set_password(default_password)
                        user.save()

                    # Update or create the Alumni record
                    alumni, created = Alumni.objects.update_or_create(
                        user=user,
                        defaults={
                            'roll_no': row['roll_no'],
                            'graduation_year': row['graduation_year'],
                            'gender': row['gender'],
                            'major': row['major'],
                            'phone': row['phone'],
                            'location': row['location'],
                            'current_position': row['current_position'],
                            'company': row['company'],
                            'bio': row.get('bio', ''),  # Optional bio field
                        }
                    )

                    # Automatically approve alumni by setting the approval_status of User model
                    user.approval_status = True
                    user.save()

                messages.success(request, "Alumni imported successfully.")
            except Exception as e:
                messages.error(request, f"Error processing file: {e}")

    return redirect('view_alumni_list')  # Correct URL for redirect
