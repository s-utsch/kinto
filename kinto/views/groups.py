import colander

from cliquet import resource
from cliquet import schema

from cliquet.authorization import get_object_id

from kinto.views import (ProtectedViewSet, NameGenerator, object_exists_or_404,
                         handle_default_bucket)


class GroupSchema(schema.ResourceSchema):
    members = colander.SchemaNode(colander.Sequence(),
                                  colander.SchemaNode(colander.String()))


@resource.register(name='group',
                   collection_path='/buckets/{{bucket_id}}/groups',
                   record_path='/buckets/{{bucket_id}}/groups/{{id}}',
                   viewset=ProtectedViewSet())
class Group(resource.ProtectedResource):

    mapping = GroupSchema()

    def __init__(self, *args, **kwargs):
        super(Group, self).__init__(*args, **kwargs)
        self.collection.id_generator = NameGenerator()

    def _get_record_or_404(self, record_id):
        handle_default_bucket(self, self.bucket_id)
        return super(Group, self)._get_record_or_404(record_id)

    def get_parent_id(self, request):
        self.bucket_id = request.matchdict['bucket_id']
        parent_id = '/buckets/%s' % self.bucket_id
        return parent_id

    def collection_delete(self):
        filters = self._extract_filters()
        groups, _ = self.collection.get_records(filters=filters)
        body = super(Group, self).collection_delete()
        permission = self.request.registry.permission
        for group in groups:
            # Remove the group's principal from all members of the group.
            for member in group['members']:
                group_id = '%s/%s' % (get_object_id(self.request.path),
                                      group['id'])
                permission.remove_user_principal(
                    member,
                    group_id)
        return body

    def delete(self):
        group = self._get_record_or_404(self.record_id)
        permission = self.request.registry.permission
        body = super(Group, self).delete()
        object_id = get_object_id(self.request.path)
        for member in group['members']:
            # Remove the group's principal from all members of the group.
            permission.remove_user_principal(member, object_id)
        return body

    def process_record(self, new, old=None):
        if old is None:
            existing_record_members = set([])
        else:
            existing_record_members = set(old.get('members', []))
        new_record_members = set(new['members'])
        new_members = new_record_members - existing_record_members
        removed_members = existing_record_members - new_record_members

        permission = self.request.registry.permission
        for member in new_members:
            # Add the group to the member principal.
            group_id = get_object_id(self.request.path)
            permission.add_user_principal(member, group_id)

        for member in removed_members:
            # Remove the group from the member principal.
            group_id = get_object_id(self.request.path)
            permission.remove_user_principal(member, group_id)

        return new
