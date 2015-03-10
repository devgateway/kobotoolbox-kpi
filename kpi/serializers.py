from django.forms import widgets
from rest_framework import serializers
from rest_framework.pagination import PaginationSerializer
from rest_framework.reverse import reverse_lazy, reverse
from kpi.models import SurveyAsset
from kpi.models import Collection

from django.contrib.auth.models import User
import json

class Paginated(PaginationSerializer):
    root = serializers.SerializerMethodField('get_parent_url', read_only=True)

    def get_parent_url(self, obj):
        request = self.context.get('request', None)
        return reverse_lazy('api-root', request=request)

import json
from rest_framework import serializers

class WritableJSONField(serializers.Field):
    """ Serializer for JSONField -- required to make field writable"""
    def to_internal_value(self, data):
        return json.loads(data)
    def to_representation(self, value):
        return value


class SurveyAssetSerializer(serializers.HyperlinkedModelSerializer):
    ownerName = serializers.ReadOnlyField(source='owner.username')
    owner = serializers.HyperlinkedRelatedField(view_name='user-detail', lookup_field='username', \
                                                read_only=True)
    parent = serializers.SerializerMethodField('get_parent_url', read_only=True)
    assetType = serializers.ReadOnlyField(read_only=True, source='asset_type')
    settings = WritableJSONField(read_only=True)
    collectionName = serializers.ReadOnlyField(read_only=True, source='collection.name')
    ss_json = serializers.SerializerMethodField('_to_ss_json', read_only=True)

    class Meta:
        model = SurveyAsset
        lookup_field = 'uid'
        fields = ('url', 'parent', 'owner', 'ownerName', 'collection',
                    'settings', 'assetType', 'ss_json',
                    'uid', 'name', 'collectionName', )
        extra_kwargs = {
            'collection': {
                'lookup_field': 'uid',
            },
        }

    def _to_ss_json(self, obj):
        return obj._to_ss_structure()

    def _content(self, obj):
        return json.dumps(obj.content)

    def get_parent_url(self, obj):
        request = self.context.get('request', None)
        return reverse_lazy('surveyasset-list', request=request)

    def _table_url(self, obj):
        request = self.context.get('request', None)
        return reverse('surveyasset-table-view', args=(obj.uid,), request=request)

    # def _get_collection_route(self, obj):
    #     '''
    #     it would be nice to get these urls routing to the uid, instead of the numeric id
    #     '''
    #     request = self.context.get('request', None)
    #     return reverse('collection-detail', args=(obj.collection.uid,), request=request)

class SurveyAssetListSerializer(SurveyAssetSerializer):
    class Meta(SurveyAssetSerializer.Meta):
        fields = ('url', 'owner', 'ownerName', 'collection',
                    'assetType', 'uid', 'name', 'collectionName', )



class UserSerializer(serializers.HyperlinkedModelSerializer):
    survey_assets = serializers.HyperlinkedRelatedField(many=True,
                 view_name='surveyasset-detail', read_only=True)

    class Meta:
        model = User
        fields = ('url', 'username', 'survey_assets', 'collections')
        # list_serializer_class = UserListSerializer
        lookup_field = 'username'
        extra_kwargs = {
            'collections': {
                'lookup_field': 'uid',
            },
        }

class CollectionSerializer(serializers.HyperlinkedModelSerializer):
    owner = serializers.HyperlinkedRelatedField(view_name='user-detail', \
                lookup_field='username', read_only=True)


    class Meta:
        model = Collection
        fields = ('name', 'url', 'survey_assets', 'uid', 'owner',)
        lookup_field = 'uid'
        extra_kwargs = {
            'survey_assets': {
                'lookup_field': 'uid',
            },
        }
