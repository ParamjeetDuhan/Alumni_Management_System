from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import Alumni, Event, Job, News, User 

# Alumni Registration Form
class AlumniRegistrationForm(UserCreationForm):
    GENDER_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
        ('prefer not to say', 'Prefer not to say'),
    ]

    first_name = forms.CharField(max_length=50, required=True)
    last_name = forms.CharField(max_length=50, required=True)
    email = forms.EmailField(required=True)
    roll_no = forms.CharField(max_length=20, required=True)
    graduation_year = forms.IntegerField(required=True)
    major = forms.CharField(max_length=100, required=True)
    phone = forms.CharField(max_length=15, required=True)
    location = forms.CharField(max_length=100, required=True)
    current_position = forms.CharField(max_length=100, required=True)
    company = forms.CharField(max_length=100, required=True)
    bio = forms.CharField(widget=forms.Textarea, required=True)
    gender = forms.ChoiceField(choices=GENDER_CHOICES, required=True)

    password = forms.CharField(widget=forms.PasswordInput, label="Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput, label="Confirm Password")

    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'roll_no',
            'graduation_year', 'major', 'phone', 'location',
            'current_position', 'company', 'bio', 'gender',
            'password', 'confirm_password'
        ]

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match.")
        return cleaned_data

    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.email = self.cleaned_data['email']
        user.username = self.cleaned_data['email']  # use email as username
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        user.set_password(self.cleaned_data['password'])
        user.role = 'alumni'

        if commit:
            user.save()
            Alumni.objects.create(
                user=user,
                roll_no=self.cleaned_data['roll_no'],
                graduation_year=self.cleaned_data['graduation_year'],
                major=self.cleaned_data['major'],
                phone=self.cleaned_data['phone'],
                location=self.cleaned_data['location'],
                current_position=self.cleaned_data['current_position'],
                company=self.cleaned_data['company'],
                bio=self.cleaned_data['bio'],
                gender=self.cleaned_data['gender']
            )
        return user

# Event Form
class EventForm(forms.ModelForm):
    event_name = forms.CharField(max_length=100, required=True)
    event_description = forms.CharField(widget=forms.Textarea, required=True)
    event_date = forms.DateTimeField(
        required=True,
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local'}),
    )
    location = forms.CharField(max_length=100, required=True)

    class Meta:
        model = Event
        fields = ['event_name', 'event_description', 'event_date', 'location']

# Job Form
class JobForm(forms.ModelForm):
    job_title = forms.CharField(max_length=100, required=True)
    company = forms.CharField(max_length=100, required=True)
    location = forms.CharField(max_length=100, required=True)
    description = forms.CharField(widget=forms.Textarea, required=True)
    expiration_date = forms.DateTimeField(
        required=True,
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local'}),
    )
    registration_link = forms.URLField(
        required=False,
        widget=forms.URLInput(attrs={'placeholder': 'https://example.com/register'}),
        help_text="Optional: Provide a link for application."
    )

    class Meta:
        model = Job
        fields = ['job_title', 'company', 'location', 'description','registration_link', 'expiration_date']

# News Form
class NewsForm(forms.ModelForm):
    title = forms.CharField(max_length=100, required=True)
    content = forms.CharField(widget=forms.Textarea, required=True)

    class Meta:
        model = News
        fields = ['title', 'content']

#import alumni
class AlumniImportForm(forms.Form):
    file = forms.FileField()

# Custom Change Password Form
class CustomPasswordChangeForm(forms.Form):
    old_password = forms.CharField(
        label="Old Password",
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'})
    )
    new_password1 = forms.CharField(
        label="New Password",
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text="Password must be at least 8 characters, include 1 uppercase, 1 lowercase, 1 number, and 1 special character."
    )
    new_password2 = forms.CharField(
        label="Confirm New Password",
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'})
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_old_password(self):
        old_password = self.cleaned_data.get("old_password")
        if not self.user.check_password(old_password):
            raise forms.ValidationError("Old password is incorrect.")
        return old_password

    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get("new_password1")
        new_password2 = cleaned_data.get("new_password2")

        # Password confirmation match
        if new_password1 and new_password2 and new_password1 != new_password2:
            raise forms.ValidationError("New passwords do not match.")

        # Password strength validation
        import re
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$'
        if not re.match(pattern, new_password1):
            raise forms.ValidationError(
                "Password must be at least 8 characters long and include 1 uppercase, 1 lowercase, 1 number, and 1 special character."
            )

        return cleaned_data

    def save(self, commit=True):
        new_password = self.cleaned_data["new_password1"]
        self.user.set_password(new_password)
        if commit:
            self.user.save()
        return self.user
