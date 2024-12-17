from rest_framework import serializers
from .models import User
from api.validation import *

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs={
            'password': {'write_only':True}
        }

    def validate(self, attrs):
        validation_errors = {}

        username_error = username_validator(attrs.get('username'))
        if username_error:
            validation_errors['username'] = username_error


        email_error = email_validator(attrs.get('email'))
        if email_error:
            validation_errors['email'] = email_error


        password_error = password_validator(attrs.get('password'))
        if password_error:
            validation_errors['password'] = password_error

        if validation_errors:
            raise serializers.ValidationError(validation_errors)

        return attrs
    
    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        user.is_active = False
        user.save()
        return user    


class UserLoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(required=True)
    # email = serializers.EmailField(required=False)
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        # model = User
        fields = ['username_or_email', 'password']
        # extra_kwargs={
        #     'password': {'write_only':True}
        # }


class OTPLoginRequestSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(required=True)
    ip_address = serializers.IPAddressField()

    class Meta:
        fields = ['username_or_email', 'ip_address']


class OTPLoginVerifySerializer(serializers.Serializer):
    user_id = serializers.CharField(required=True)
    otp_code = serializers.CharField(required=True, max_length=6) 
    ip_address = serializers.IPAddressField()

    class Meta:
        fields = ['user_id', 'otp_code', 'ip_address']


class ForgetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    class Meta:
        fields = ['email']


class ForgetPasswordResetSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, required=True)
    re_new_password = serializers.CharField(write_only=True, required=True)
    token = serializers.CharField(write_only=True, required=True)
    uidb64 = serializers.CharField(write_only=True, required=True)

    class Meta:
        fields = ['new_password', 're_new_password', 'token', 'uidb64']