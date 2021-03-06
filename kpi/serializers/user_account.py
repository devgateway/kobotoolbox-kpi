# coding: utf-8
from django.contrib.auth.models import User
from rest_framework import serializers

from kpi.forms import USERNAME_REGEX
from kpi.forms import USERNAME_MAX_LENGTH
from kpi.forms import USERNAME_INVALID_MESSAGE


class UserAccountSerializer(serializers.ModelSerializer):
    username = serializers.RegexField(
        regex=USERNAME_REGEX,
        max_length=USERNAME_MAX_LENGTH,
        error_messages={'invalid': USERNAME_INVALID_MESSAGE}
    )
    email = serializers.EmailField(default="")

    class Meta:
        model = User
        fields = (
            'username',
            'password',
            'first_name',
            'last_name',
            'email',
            'is_active',
        )
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': False}
        }

    def create(self, validated_data):
        user = User()
        user.set_password(validated_data['password'])
        non_password_fields = list(self.Meta.fields)
        try:
            non_password_fields.remove('password')
        except ValueError:
            pass
        for field in non_password_fields:
            try:
                setattr(user, field, validated_data[field])
            except KeyError:
                pass
        user.save()
        return user

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            pwd = validated_data['password']
            if pwd is not None:
                instance.set_password(pwd)
            try:
                del validated_data["password"]
            except AttributeError:
                pass
        return super().update(instance, validated_data)
