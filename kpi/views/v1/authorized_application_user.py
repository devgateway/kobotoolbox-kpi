# coding: utf-8
from django.contrib.auth.models import User
from rest_framework import viewsets, mixins, exceptions

from kpi.models import AuthorizedApplication
from kpi.models.authorized_application import StaffTokenAuthentication
from kpi.serializers import UserAccountSerializer


class AuthorizedApplicationUserViewSet(mixins.CreateModelMixin,
                                       viewsets.GenericViewSet):
    authentication_classes = [StaffTokenAuthentication]
    queryset = User.objects.all()
    serializer_class = UserAccountSerializer
    lookup_field = 'username'

    def create(self, request, *args, **kwargs):
        if type(request.auth) is not AuthorizedApplication:
            # Only specially-authorized applications are allowed to create
            # users via this endpoint
            raise exceptions.PermissionDenied()
        return super().create(request, *args, **kwargs)
