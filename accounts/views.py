from datetime import timedelta

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.tokens import default_token_generator

from django.views.decorators.csrf import csrf_exempt

from django.core.exceptions import ObjectDoesNotExist, ValidationError

from django.utils import timezone
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.utils.timezone import now

from .serializers import *
from api.renderers import ResponseRenderer
from helper.Generator import generate_token
from helper.EmailSender import EmailSender

User = get_user_model()

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegistrationView(APIView):
    renderer_classes = [ResponseRenderer]

    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            username = serializer.validated_data.get('username')
            email = serializer.validated_data.get('email')
            user = serializer.save()

            # Sending the verification mail to user 
            reset_url = generate_token(request, user, 'verify-mail')
            subject = 'Email Confirmation'
            page = 'email_verification_mail.html'
            mail = EmailSender(subject, [email], user=username, template_name=page, token=reset_url)
            mail.sending_mail()
            return Response({'message' : 'Registration Successfull'}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    renderer_classes = [ResponseRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            username_or_email = serializer.validated_data.get('username_or_email')
            password = serializer.validated_data.get('password')

            email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            identifier = "Email" if re.match(email_pattern, username_or_email) else "Username"

            user_data = None
            if identifier == 'Email':
                user_data = User.objects.filter(email=username_or_email).values('username', 'email', 'is_active', 'is_email_verified').first()
            elif identifier == 'Username':
                user_data = User.objects.filter(username=username_or_email).values('username', 'email', 'is_active', 'is_email_verified').first()

            if not user_data:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            if not user_data['is_active'] or not user_data['is_email_verified']:
                return Response({"error": "Email is not verified"}, status=status.HTTP_403_FORBIDDEN)

            user = authenticate(request, username=user_data['username'], password=password)

            if user is not None:
                token = get_tokens_for_user(user)
                return Response({
                        "message": "Login Successfully",
                        "token" : token,
                    }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid credentials"}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    renderer_classes = [ResponseRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # refresh_token = request.data.get("token", {}).get("refresh")
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Refresh token not provided"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
@csrf_exempt
def verifyMail(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
        return Response({"error" : "Invalid verification link."}, status=status.HTTP_400_BAD_REQUEST)
    
    if not default_token_generator.check_token(user, token):
        return Response({"error" : "Verification link is invalid or has expired."}, status=status.HTTP_400_BAD_REQUEST)
    
    if user.is_active and user.is_email_verified:
        return Response({"message": "Email is already verified."}, status=status.HTTP_200_OK)
    
    verification_deadline = user.date_joined + timedelta(days=1)
    if now() > verification_deadline:
        return Response({"error": "Verification link has expired. Please re-register."}, status=status.HTTP_400_BAD_REQUEST)
    
    # Activate the user and mark email as verified
    user.is_active = True
    user.is_email_verified = True
    user.save()

    return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)