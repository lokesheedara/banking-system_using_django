from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import LoginView
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse_lazy, reverse
from django.views.generic import TemplateView, RedirectView
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .forms import UserRegistrationForm, UserAddressForm
User = get_user_model()

class UserRegistrationView(TemplateView):
    """View for user registration"""
    model = User
    form_class = UserRegistrationForm
    template_name = 'accounts/user_registration.html'
    def dispatch(self, request, *args, **kwargs):
        """Redirect authenticated users to transaction report page"""
        if self.request.user.is_authenticated:
            return HttpResponseRedirect(reverse_lazy('transactions:transaction_report'))
        return super().dispatch(request, *args, **kwargs)

    def send_activation_email(self, user):
        """Send activation email to user"""
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        activation_url = reverse('accounts:activate_email', kwargs={
                                  'uidb64': uid, 'token': token})
        activation_url = self.request.build_absolute_uri(activation_url)
        context = {'user': user, 'activation_url': activation_url}
        message = render(
            self.request, 'accounts/activation_email.html', context)
        user.email_user(subject='Activate your account',
                         message=message.content.decode('utf-8'))

    def post(self, request, *args, **kwargs):
        """Handle post request"""
        registration_form = UserRegistrationForm(self.request.POST)
        address_form = UserAddressForm(self.request.POST)
        if registration_form.is_valid() and address_form.is_valid():
            user = registration_form.save(commit=False)
            user.is_active = False
            user.save()
            address = address_form.save(commit=False)
            address.user = user
            address.save()
            self.send_activation_email(user)
            messages.success(
                self.request,
                (
                    f'Thank You For Creating A Bank Account. '
                    f'Please check your email to activate your account.'
                )
            )
            return HttpResponseRedirect(reverse_lazy('accounts:user_login'))
        return self.render_to_response(
            self.get_context_data(
                registration_form=registration_form,
                address_form=address_form
            )
        )

    def get_context_data(self, **kwargs):
        """Get context data"""
        if 'registration_form' not in kwargs:
            kwargs['registration_form'] = UserRegistrationForm()
        if 'address_form' not in kwargs:
            kwargs['address_form'] = UserAddressForm()
        return super().get_context_data(**kwargs)
class UserLoginView(LoginView):
    """View for user login"""
    template_name='accounts/user_login.html'
    redirect_authenticated_user = True
class LogoutView(RedirectView):
    """View for user logout"""
    pattern_name = 'home'
    def get_redirect_url(self, *args, **kwargs):
        """Logout user and redirect to home page"""
        if self.request.user.is_authenticated:
            logout(self.request)
        return super().get_redirect_url(*args, **kwargs)
def activate_email(request, uidb64, token):
    """View to activate user account"""
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Your account has been activated. You can now login.')
    else:
        messages.error(request, 'Invalid activation link.')
    return HttpResponseRedirect(reverse_lazy('accounts:user_login'))
def verify_email(request, uidb64, token):
    """View to verify user email"""
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user and default_token_generator.check_token(user, token):
        user.email_verified = True
        user.save()
        messages.success(request, 'Your email has been verified.')
    else:
        messages.error(request, 'Invalid verification link.')
    return HttpResponseRedirect(reverse_lazy('accounts:user_login'))
