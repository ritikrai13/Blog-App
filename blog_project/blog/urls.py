from django.urls import path
from .views import SignupView, LoginView, ForgotPasswordView,ValidateOtpView
from .views import SendVerificationEmail, VerifyEmail

from .views import UpdateUserView, DeleteUserView, CreateBlogView, ListBlogView, UpdateBlogView, DeleteBlogView

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('api/validate-otp/', ValidateOtpView.as_view(), name='validate-otp'),
    path('send-verification/', SendVerificationEmail.as_view(), name='send-verification'),
    path('verify-email/<uuid:token>/', VerifyEmail.as_view(), name='verify-email'),
    path('update-user/', UpdateUserView.as_view(), name='update-user'),
    path('delete-user/', DeleteUserView.as_view(), name='delete-user'),
     path('blog/', ListBlogView.as_view(), name='list-blogs'),
    path('blog/create/', CreateBlogView.as_view(), name='create-blog'),
    path('blog/<int:blog_id>/update/', UpdateBlogView.as_view(), name='update-blog'),
    path('blog/<int:blog_id>/delete/', DeleteBlogView.as_view(), name='delete-blog'),
]
