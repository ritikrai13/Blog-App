from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from .models import BlogUser,PasswordResetRequest
from .serializers import SignupSerializer, LoginSerializer, ForgotPasswordSerializer,UpdateUserSerializer
import random
from django.urls import reverse

from django.shortcuts import get_object_or_404

from django.utils import timezone
from .models import EmailVerification
from django.contrib.auth.tokens import default_token_generator
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .models import Blog
from .serializers import BlogSerializer
class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

          
            verification = EmailVerification.objects.create(user=user)
            verification_link = f"https://www.youtube.com/verify-email/{verification.token}/"
            send_mail(
                "Verify Your Email",
                f"Click the link to verify your email: {verification_link}",
                "noreply@blog.com",
                [user.email]
            )
            
            return Response({"message": "User created successfully. A verification email has been sent."})
        return Response(serializer.errors, status=400)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "Login successful.",
                "user": {
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name
                },
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token)
                }
            })
        return Response(serializer.errors, status=400)




class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                user = BlogUser.objects.get(email=email)
            except BlogUser.DoesNotExist:
                return Response({"error": "User with this email does not exist"}, status=400)

            
            otp = str(random.randint(100000, 999999))

           
            reset_request, created = PasswordResetRequest.objects.get_or_create(user=user)
            reset_request.otp = otp
            reset_request.save()

            
            send_mail(
                "Password Reset",
                f"Use this OTP to reset your password: {otp}",
                "noreply@blog.com",
                [email],
            )

            return Response({"message": "Password reset email sent."})
        return Response(serializer.errors, status=400)



class ValidateOtpView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')

        if not email or not otp or not new_password:
            return Response({"error": "Email, OTP and new password are required"}, status=400)

        try:
            user = BlogUser.objects.get(email=email)
        except BlogUser.DoesNotExist:
            return Response({"error": "User with this email does not exist"}, status=400)

        try:
            reset_request = PasswordResetRequest.objects.get(user=user, otp=otp)
        except PasswordResetRequest.DoesNotExist:
            return Response({"error": "Invalid OTP"}, status=400)

        if reset_request.is_expired():
            return Response({"error": "OTP has expired"}, status=400)

        
        user.set_password(new_password)
        user.save()

        
        reset_request.delete()

        return Response({"message": "Password reset successfully"})




class SendVerificationEmail(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        
        if not email:
            return Response({"error": "Email is required"}, status=400)

        try:
            user = BlogUser.objects.get(email=email)
        except BlogUser.DoesNotExist:
            return Response({"error": "User does not exist"}, status=400)

        verification = EmailVerification.objects.create(user=user)

        
        verification_link = f"https://www.youtube.com/verify-email/{verification.token}/"
        send_mail(
            "Verify Your Email",
            f"Click the link to verify your email: {verification_link}",
            "noreply@blog.com",
            [email]
        )

        return Response({"message": "Verification email sent successfully"})

class VerifyEmail(APIView):
    permission_classes = [AllowAny]

    def get(self, request, token):
        verification = get_object_or_404(EmailVerification, token=token)
    

        if verification.is_expired():
            return Response({"error": "Verification token has expired"}, status=400)

        if verification.is_verified:
            return Response({"message": "Email already verified"}, status=200)

        
        verification.user.is_active = True
        verification.user.save()
        verification.is_verified = True
        verification.save()

        return Response({"message": "Email successfully verified"})



class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = UpdateUserSerializer(instance=request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User updated successfully", "user": serializer.data})
        return Response(serializer.errors, status=400)


class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.is_deleted = True
        user.save()
        return Response({"message": "User deleted successfully"})



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .models import Blog
from .serializers import BlogSerializer
from django.db import IntegrityError

class CreateBlogView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            return Response({"error": "Authentication is required."}, status=status.HTTP_401_UNAUTHORIZED)

        # Prepare data, but do not manually assign 'author'
        data = request.data
        try:
            serializer = BlogSerializer(data=data)
            if serializer.is_valid():
                # The author will automatically be set from the validated data
                serializer.save(author=request.user)
                return Response({"message": "Blog created successfully", "blog": serializer.data}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as e:
            return Response({"error": f"Integrity error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

class ListBlogView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        blogs = Blog.objects.all()
        serializer = BlogSerializer(blogs, many=True)
        return Response(serializer.data)


class UpdateBlogView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, blog_id):
        try:
            blog = Blog.objects.get(id=blog_id, author=request.user)
        except Blog.DoesNotExist:
            return Response({"error": "Blog not found or you are not the author."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = BlogSerializer(blog, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Blog updated successfully", "blog": serializer.data})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteBlogView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, blog_id):
        try:
            blog = Blog.objects.get(id=blog_id, author=request.user)
        except Blog.DoesNotExist:
            return Response({"error": "Blog not found or you are not the author."}, status=status.HTTP_404_NOT_FOUND)
        
        blog.delete()
        return Response({"message": "Blog deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
