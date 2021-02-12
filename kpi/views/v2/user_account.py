# coding: utf-8
from django.contrib.auth.models import User
from django.http import Http404
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, mixins, viewsets, status, generics

from kpi.models.authorized_application import StaffTokenAuthentication
from kpi.serializers.user_account import UserAccountSerializer


class UsernameConflict(exceptions.APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = _('Username already exists.')
    default_code = 'conflict'


class UserAccountViewSet(viewsets.GenericViewSet,
                         mixins.RetrieveModelMixin,
                         mixins.CreateModelMixin,
                         mixins.UpdateModelMixin):
    authentication_classes = [StaffTokenAuthentication]
    queryset = User.objects.all()
    serializer_class = UserAccountSerializer
    lookup_field = 'username'

    def create(self, request, *args, **kwargs):
        try:
            queryset = self.filter_queryset(self.get_queryset())
            filter_kwargs = {self.lookup_field: request.data[self.lookup_field]}
            obj = generics.get_object_or_404(queryset, **filter_kwargs)
            # May raise a permission denied
            self.check_object_permissions(self.request, obj)
            raise UsernameConflict
        except Http404:
            pass
        return super().create(request, *args, **kwargs)
