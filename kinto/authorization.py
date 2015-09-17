from six import text_type
from uuid import UUID

from cliquet import authorization as cliquet_authorization
from cliquet import utils as cliquet_utils
from pyramid.security import IAuthorizationPolicy
from zope.interface import implementer


# Vocab really matters when you deal with permissions. Let's do a quick recap
# of the terms used here:
#
# Object URI:
#    An unique identifier for an object.
#    for instance, /buckets/blog/collections/articles/records/article1
#
# Object:
#    A common denomination of an object (e.g. "collection" or "record")
#
# Unbound permission:
#    A permission not bound to an object (e.g. "create")
#
# Bound permission:
#    A permission bound to an object (e.g. "collection:create")

# Dictionary which list all permissions a given permission enables.
PERMISSIONS_INHERITANCE_TREE = {
    'bucket:write': {
        'bucket': ['write']
    },
    'bucket:read': {
        'bucket': ['write', 'read']
    },
    'bucket:group:create': {
        'bucket': ['write', 'group:create']
    },
    'bucket:collection:create': {
        'bucket': ['write', 'collection:create']
    },
    'group:write': {
        'bucket': ['write'],
        'group': ['write']
    },
    'group:read': {
        'bucket': ['write', 'read'],
        'group': ['write', 'read']
    },
    'collection:write': {
        'bucket': ['write'],
        'collection': ['write'],
    },
    'collection:read': {
        'bucket': ['write', 'read'],
        'collection': ['write', 'read'],
    },
    'collection:record:create': {
        'bucket': ['write'],
        'collection': ['write', 'record:create']
    },
    'record:write': {
        'bucket': ['write'],
        'collection': ['write'],
        'record': ['write']
    },
    'record:read': {
        'bucket': ['write', 'read'],
        'collection': ['write', 'read'],
        'record': ['write', 'read']
    }
}

DEFAULT_BUCKET_NAME = 'default'


def get_object_type(object_uri):
    """Return the type of an object from its id."""

    obj_parts = object_uri.split('/')
    if len(obj_parts) % 2 == 0:
        object_uri = '/'.join(obj_parts[:-1])

    # Order matters here. More precise is tested first.
    if 'records' in object_uri:
        obj_type = 'record'
    elif 'collections' in object_uri:
        obj_type = 'collection'
    elif 'groups' in object_uri:
        obj_type = 'group'
    elif 'buckets' in object_uri:
        obj_type = 'bucket'
    else:
        obj_type = None
    return obj_type


def build_permission_tuple(obj_type, unbound_permission, obj_parts):
    """Returns a tuple of (object_uri, unbound_permission)"""
    PARTS_LENGTH = {
        'bucket': 3,
        'collection': 5,
        'group': 5,
        'record': 7
    }
    if obj_type not in PARTS_LENGTH:
        raise ValueError('Invalid object type: %s' % obj_type)

    if PARTS_LENGTH[obj_type] > len(obj_parts):
        raise ValueError('You cannot build children keys from its parent key.'
                         'Trying to build type "%s" from object key "%s".' % (
                             obj_type, '/'.join(obj_parts)))
    length = PARTS_LENGTH[obj_type]

    return ('/'.join(obj_parts[:length]), unbound_permission)


def build_permissions_set(object_uri, unbound_permission,
                          inheritance_tree=None):
    """Build a set of all permissions that can grant access to the given
    object URI and unbound permission.

    >>> build_required_permissions('/buckets/blog', 'write')
    set(('/buckets/blog', 'write'))

    """

    if inheritance_tree is None:
        inheritance_tree = PERMISSIONS_INHERITANCE_TREE

    obj_type = get_object_type(object_uri)

    # Unknown object type, does not map the INHERITANCE_TREE.
    # In that case, the set of related permissions is empty.
    if obj_type is None:
        return set()

    bound_permission = '%s:%s' % (obj_type, unbound_permission)
    granters = set()

    obj_parts = object_uri.split('/')
    for obj, permission_list in inheritance_tree[bound_permission].items():
        for permission in permission_list:
            granters.add(build_permission_tuple(obj, permission, obj_parts))

    return granters


# XXX: May need caching
def groupfinder(userid, request):
    authn_type = request.authn_type
    prefixed_userid = '%s:%s' % (authn_type.lower(), userid)
    return request.registry.permission.user_principals(prefixed_userid)


@implementer(IAuthorizationPolicy)
class AuthorizationPolicy(cliquet_authorization.AuthorizationPolicy):
    def permits(self, context, principals, permission):

        print context, context.on_default_bucket, permission
        if context.on_default_bucket:
            return True
        return super(AuthorizationPolicy, self).permits(context,
                                                        principals,
                                                        permission)

    def get_bound_permissions(self, *args, **kwargs):
        return build_permissions_set(*args, **kwargs)


class RouteFactory(cliquet_authorization.RouteFactory):
    def __init__(self, request):
        self.on_default_bucket = False
        # Default bucket requires authentication.
        if request.prefixed_userid:
            id_key = 'bucket_id'
            if id_key not in request.matchdict:
                id_key = 'id'
            bucket_id = request.matchdict.get(id_key)
            if bucket_id == DEFAULT_BUCKET_NAME:
                self.on_default_bucket = True

        # Replace the bucket id `default` by a hmac of userid.
        settings = request.registry.settings
        hmac_secret = settings['cliquet.userid_hmac_secret']
        # Build the user unguessable bucket_id UUID from its user_id
        digest = cliquet_utils.hmac_digest(hmac_secret,
                                           request.prefixed_userid)
        self.hmac_userid = text_type(UUID(digest[:32]))

        if self.on_default_bucket:
            request.matchdict[id_key] = self.hmac_userid

        super(RouteFactory, self).__init__(request)

    def get_object_id(self, request):
        object_uri = super(RouteFactory, self).get_object_id(request)
        if self.on_default_bucket:
            object_uri = object_uri.replace(DEFAULT_BUCKET_NAME,
                                                 self.hmac_userid)
        return object_uri
