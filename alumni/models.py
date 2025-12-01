from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser

# Custom User model extending AbstractUser
class User(AbstractUser):
    ROLE_CHOICES = [
        ('superadmin', 'Super Admin'),
        ('contentmanager', 'Content Manager'),
        ('eventmanager', 'Event Manager'),
        ('alumni', 'Alumni'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='alumni')
    approval_status = models.BooleanField(default=False)  # Approval status for all users

    # Check if the user is an admin
    def is_admin(self):
        return self.role in ['superadmin', 'contentmanager', 'eventmanager']

# Alumni model - Alumni details
class Alumni(models.Model):
    GENDER_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
        ('prefer not to say', 'Prefer not to say'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    roll_no = models.CharField(max_length=20, unique=True)
    graduation_year = models.IntegerField(default=2000)
    major = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    location = models.CharField(max_length=100)
    current_position = models.CharField(max_length=100)
    company = models.CharField(max_length=100)
    bio = models.TextField()
    linkedin = models.URLField(blank=True, null=True)
    github = models.URLField(blank=True, null=True)
    twitter = models.URLField(blank=True, null=True)
    website = models.URLField(blank=True, null=True)
    instagram = models.URLField(blank=True, null=True)
    facebook = models.URLField(blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', default='profile_pics/default.png')
    gender = models.CharField(max_length=20, choices=GENDER_CHOICES, default='prefer_not_to_say')

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"

# Event model - Event details
class Event(models.Model):
    event_name = models.CharField(max_length=100)
    event_description = models.TextField()
    event_date = models.DateTimeField()
    location = models.CharField(max_length=100)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        ordering = ['-event_date']  # Latest events first

    def __str__(self):
        return self.event_name

# Job model - Job posting details
class Job(models.Model):
    job_title = models.CharField(max_length=100)
    company = models.CharField(max_length=100)
    location = models.CharField(max_length=100)
    description = models.TextField()
    posted_by = models.ForeignKey(User, on_delete=models.CASCADE)
    expiration_date = models.DateTimeField()
    registration_link = models.URLField(blank=True, null=True)

    class Meta:
        ordering = ['-expiration_date']  # Expire soonest jobs first

    def __str__(self):
        return self.job_title

# News model - News posting details
class News(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-id']  # Latest news first

    def __str__(self):
        return self.title
