from django.urls import path

from .views import UserRegistrationView, LogoutView, UserLoginView,activate_email,verify_email


app_name = 'accounts'

urlpatterns = [
    # User registration views
    path('accounts/register/', UserRegistrationView.as_view(),
         name='user_registration'),
    path('accounts/activate/<str:uidb64>/<str:token>/',
         activate_email, name='activate_email'),
    path('accounts/verify/<str:uidb64>/<str:token>/',
         verify_email, name='verify_email'),
    # User authentication views
    path('accounts/login/', UserLoginView.as_view(), name='user_login'),
    path('accounts/logout/', LogoutView.as_view(), name='user_logout'),
]
