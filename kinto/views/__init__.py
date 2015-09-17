import random
import string

from cliquet import resource as cliquet_resource
from cliquet.storage import generators, exceptions
from cliquet.utils import build_request
from pyramid import httpexceptions

from kinto import authorization


class NameGenerator(generators.Generator):
    def __call__(self):
        ascii_letters = ('abcdefghijklmopqrstuvwxyz'
                         'ABCDEFGHIJKLMOPQRSTUVWXYZ')
        alphabet = ascii_letters + string.digits + '-_'
        letters = [random.choice(ascii_letters + string.digits)]
        letters += [random.choice(alphabet) for x in range(7)]
        return ''.join(letters)


def object_exists_or_404(request, collection_id, object_id, parent_id=''):
    storage = request.registry.storage
    try:
        return storage.get(collection_id=collection_id,
                           parent_id=parent_id,
                           object_id=object_id)
    except exceptions.RecordNotFoundError:
        # XXX: We gave up putting details about parent id here (See #53).
        raise httpexceptions.HTTPNotFound()


class ProtectedViewSet(cliquet_resource.ProtectedViewSet):
    def get_service_arguments(self):
        args = super(ProtectedViewSet, self).get_service_arguments()
        args['factory'] = authorization.RouteFactory
        return args


def handle_default_bucket(resource, bucket_id, collection_id=None):
    on_default_bucket = (resource.context and
                         resource.context.on_default_bucket)
    if not on_default_bucket:
        return

    from kinto.views.buckets import Bucket
    from kinto.views.collections import Collection

    is_creation = resource.request.method.lower() in ('put', 'post')

    is_bucket = isinstance(resource, Bucket)
    bucket_creation = is_creation and is_bucket

    if not bucket_creation:
        subrequest = build_request(resource.request, {
            'method': 'PUT',
            'path': '/buckets/%s' % bucket_id,
            'body': {"data": {}},
            'headers': {'If-None-Match': '*'.encode('utf-8')}
        })
        subrequest.registry = resource.request.registry
        subrequest.prefixed_userid = resource.request.prefixed_userid
        subrequest.matchdict = {'id': bucket_id}
        subrequest.validated = {"data": {}}
        context = authorization.RouteFactory(subrequest)
        context.resource_name = 'bucket'
        context.object_uri = '/buckets/%s' % bucket_id
        bucket_resource = Bucket(subrequest, context)
        try:
            bucket_resource.put()
        except httpexceptions.HTTPPreconditionFailed:
            pass

    if collection_id is None:
        return

    is_collection = isinstance(resource, Collection)
    collection_creation = is_creation and is_collection

    if not collection_creation:
        subrequest = build_request(resource.request, {
            'method': 'PUT',
            'path': '/buckets/%s/collections/%s' % (
                bucket_id, collection_id),
            'body': {"data": {}},
            'headers': {'If-None-Match': '*'.encode('utf-8')}
        })
        subrequest.registry = resource.request.registry
        subrequest.prefixed_userid = resource.request.prefixed_userid
        subrequest.matchdict = {'bucket_id': bucket_id, 'id': collection_id}
        subrequest.validated = {"data": {}}
        context = authorization.RouteFactory(subrequest)
        context.resource_name = 'collection'
        context.object_uri = '/buckets/%s/collections/%s' % (
                bucket_id, collection_id)
        collection_resource = Collection(subrequest, context)

        try:
            collection_resource.put()
        except httpexceptions.HTTPPreconditionFailed:
            pass
