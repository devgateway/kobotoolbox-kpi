# coding: utf-8
import datetime

from django.db import models
from django.utils.crypto import get_random_string
from django.utils.translation import ugettext_lazy as _
from django.core.validators import MinLengthValidator
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import TokenAuthentication, get_authorization_header
from rest_framework import exceptions

KEY_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
KEY_LENGTH = 60


def _generate_random_key():
    return get_random_string(KEY_LENGTH, KEY_CHARS)


class AuthorizedApplication(models.Model):
    name = models.CharField(max_length=50)
    key = models.CharField(
        max_length=KEY_LENGTH,
        validators=[MinLengthValidator(KEY_LENGTH)],
        default=_generate_random_key
    )

    def __str__(self):
        return self.name


def ten_minutes_from_now():
    return datetime.datetime.now() + datetime.timedelta(minutes=10)


class OneTimeAuthenticationKey(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    key = models.CharField(
        max_length=KEY_LENGTH,
        validators=[MinLengthValidator(KEY_LENGTH)],
        default=_generate_random_key
    )
    expiry = models.DateTimeField(default=ten_minutes_from_now)


class ApplicationTokenAuthentication(TokenAuthentication):
    model = AuthorizedApplication

    def authenticate_credentials(self, key):
        """ Mostly duplicated from TokenAuthentication, except that we return
        an AnonymousUser """
        try:
            token = self.model.objects.get(key=key)
        except self.model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))
        return AnonymousUser(), token


class RequiredTokenAuthentication(TokenAuthentication):
    """Authorization Token is required"""

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != self.keyword.lower().encode():
            msg = _('Invalid or missing token header.')
            raise exceptions.AuthenticationFailed(msg)
        return super().authenticate(request)


class StaffTokenAuthentication(RequiredTokenAuthentication):
    """Requires staff authentication"""

    def authenticate(self, request):
        user_auth_tuple = super().authenticate(request)
        user = None
        if user_auth_tuple is not None:
            user, token = user_auth_tuple
        if user is None or not user.is_staff:
            msg = _('Not allowed. Not a staff token.')
            raise exceptions.AuthenticationFailed(msg)
        return user_auth_tuple
