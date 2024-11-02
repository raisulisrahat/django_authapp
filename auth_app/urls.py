from django.urls import path
from . import views

urlpatterns = [
    path('profle/', views.Home, name='home'),
    path('login/', views.Login, name='login'),
    path('logout/', views.Logout, name='logout'),
    path('register/', views.Register, name='register'),
    # path('profile/', views.Profile, name='profile'),
    path('forgot-password/', views.Forgot, name='forgot-password'),
    path('change-password/<str:reset_id>', views.ChangePassword, name='change-password'),
    path('password-reset/<str:reset_id>', views.PasswordReset, name='password-reset'),
]