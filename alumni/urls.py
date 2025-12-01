from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
    # Public Routes
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('events/', views.view_events, name='view_events'),
    path('jobs/', views.view_jobs, name='view_jobs'),
    path('api/stats/', views.get_stats, name='get_stats'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),

    # Alumni Routes
    path('dashboard/alumni/', views.dashboard_alumni, name='dashboard_alumni'),
    path('profile/', views.my_profile, name='my_profile'),
    path('upload-profile-picture/', views.upload_profile_picture, name='upload_profile_picture'),
    path('alumni-directory/alumni/<int:alumni_id>/', views.view_alumni_profile, name='view_alumni_profile'),
    path('update-profile-field/', views.update_profile_field, name='update_profile_field'),
    path('alumni-directory/', views.alumni_directory, name='alumni_directory'),
    path('password-change/', views.password_change, name='password_change'),
    path('post/event/', views.post_event, name='post_event'),
    path('post/job/', views.post_job, name='post_job'),
    path('job/edit/<int:job_id>/', views.edit_own_job, name='edit_own_job'),
    path('event/edit/<int:event_id>/', views.edit_own_event, name='edit_own_event'),
    path('job/delete/<int:job_id>/', views.delete_own_job, name='delete_own_job'),
    path('event/delete/<int:event_id>/', views.delete_own_event, name='delete_own_event'),
    path('send_message/<int:alumni_id>/', views.send_message, name='send_message'),

    # Admin Routes 
    path('admin-dashboard/', views.dashboard_admin, name='dashboard_admin'),
    path('admin-dashboard/alumni/list/', views.view_alumni_list, name='view_alumni_list'),
    path('admin-dashboard/import-alumni/', views.import_alumni, name='import_alumni'),
    path('admin-dashboard/update-alumni-field/', views.update_alumni_field, name='update_alumni_field'),
    path('admin-dashboard/alumni/remove/<int:alumni_id>/', views.remove_alumni, name='remove_alumni'),
    path('admin-directory/alumni/<int:alumni_id>/', views.view_alumni_profiles, name='view_alumni_profiles'),
    path('admin-dashboard/alumni/bulk-remove/', views.bulk_remove_alumni, name='bulk_remove_alumni'),
    path('admin-dashboard/approve/alumni/<int:alumni_id>/', views.approve_alumni, name='approve_alumni'),
    path('admin-dashboard/decline/alumni/<int:alumni_id>/', views.decline_alumni, name='decline_alumni'),
    path('admin-dashboard/post/news/', views.post_news, name='post_news'),
    path('admin-directory/update-profile-picture/<int:user_id>/', views.admin_update_profile_picture, name='admin_update_profile_picture'),

    # ED Operations
    path('admin-dashboard/news/edit/<int:news_id>/', views.edit_news, name='edit_news'),
    path('admin-dashboard/news/delete/<int:news_id>/', views.delete_news, name='delete_news'),
    path('admin-dashboard/job/edit/<int:job_id>/', views.admin_edit_job, name='admin_edit_job'),
    path('admin-dashboard/event/edit/<int:event_id>/', views.admin_edit_event, name='admin_edit_event'),
    path('admin-dashboard/job/delete/<int:job_id>/', views.admin_delete_job, name='admin_delete_job'),
    path('admin-dashboard/event/delete/<int:event_id>/', views.admin_delete_event, name='admin_delete_event'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
