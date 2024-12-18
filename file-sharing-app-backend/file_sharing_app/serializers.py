from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *

class UserSerializer(serializers.ModelSerializer):
    def create(self, validated_data):
        user = User.objects.create(**validated_data)
        return user

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'logged_in', 'otp_base32']

class RegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'password2', 'logged_in', 'otp_base32']

    def validate(self, data):
        if 'password' not in data or 'password2' not in data:
            raise serializers.ValidationError("Both password and password confirmation are required.")
        if data['password'] != data['password2']:
            raise serializers.ValidationError("Passwords must match.")
        return data

    def create(self, validated_data):
        validated_data.pop('password2', None)
        user = User.objects.create(**validated_data)
        return user