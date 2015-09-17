import colander
import jsonschema
from cliquet import resource
from jsonschema import exceptions as jsonschema_exceptions

from kinto.views import ProtectedViewSet, NameGenerator, handle_default_bucket


class JSONSchemaMapping(colander.SchemaNode):
    def schema_type(self, **kw):
        return colander.Mapping(unknown='preserve')

    def deserialize(self, cstruct=colander.null):
        # Start by deserializing a simple mapping.
        validated = super(JSONSchemaMapping, self).deserialize(cstruct)

        # In case it is optional in parent schema.
        if not validated or validated in (colander.null, colander.drop):
            return validated

        try:
            jsonschema.Draft4Validator.check_schema(validated)
        except jsonschema_exceptions.SchemaError as e:
            self.raise_invalid(e.path.pop() + e.message)
        return validated


class CollectionSchema(resource.ResourceSchema):
    schema = JSONSchemaMapping(missing=colander.drop)

    class Options:
        preserve_unknown = True


@resource.register(name='collection',
                   collection_methods=('GET',),
                   collection_path='/buckets/{{bucket_id}}/collections',
                   record_path='/buckets/{{bucket_id}}/collections/{{id}}',
                   viewset=ProtectedViewSet())
class Collection(resource.ProtectedResource):
    mapping = CollectionSchema()
    permissions = ('read', 'write', 'record:create')

    def __init__(self, *args, **kwargs):
        super(Collection, self).__init__(*args, **kwargs)
        self.collection.id_generator = NameGenerator()

    def _get_record_or_404(self, record_id):
        handle_default_bucket(self, self.bucket_id, record_id)
        return super(Collection, self)._get_record_or_404(record_id)

    def get_parent_id(self, request):
        self.bucket_id = request.matchdict['bucket_id']
        parent_id = '/buckets/%s' % self.bucket_id
        return parent_id

    def delete(self):
        result = super(Collection, self).delete()

        # Delete records.
        storage = self.collection.storage
        parent_id = '%s/collections/%s' % (self.collection.parent_id,
                                           self.record_id)
        storage.delete_all(collection_id='record',
                           parent_id=parent_id,
                           with_deleted=False)
        storage.purge_deleted(collection_id='record', parent_id=parent_id)

        return result
