# -*- coding: utf-8 -*-

from django.db import models


class RepoTagsManager(models.Manager):

    def get_all_by_repo_id(self, repo_id):
        return super(RepoTagsManager, self).filter(repo_id=repo_id)

    def get_repo_tag_by_name(self, repo_id, tag_name):
        try:
            return super(RepoTagsManager, self).get(repo_id=repo_id, name=tag_name)
        except self.model.DoesNotExist:
            return None

    def get_repo_tag_by_id(self, repo_tag_id):
        try:
            return super(RepoTagsManager, self).get(pk=repo_tag_id)
        except self.model.DoesNotExist:
            return None

    def create_repo_tag(self, repo_id, tag_name, tag_color, is_system=False):
        try:
            return super(RepoTagsManager, self).get(repo_id=repo_id, name=tag_name, color=tag_color)
        except self.model.DoesNotExist:
            repo_tag = self.model(repo_id=repo_id, name=tag_name, color=tag_color,
                                  is_system=is_system)
            repo_tag.save()
            return repo_tag

    def delete_repo_tag(self, repo_tag_id):
        try:
            repo_tag = super(RepoTagsManager, self).get(pk=repo_tag_id)
            repo_tag.delete()
            return True
        except self.model.DoesNotExist:
            return False


class RepoTags(models.Model):

    repo_id = models.CharField(max_length=36, db_index=True)
    name = models.CharField(max_length=255, db_index=True)
    color = models.CharField(max_length=255, db_index=True)
    # CloudFile P2-07: system tags are admin-managed and read-only for everyone
    # else; user tags are editable by rw and above. The column is added by the
    # docker bootstrap (apply_tag_schema_compatibility), not by a Django
    # migration, so this field must default to False to keep native CE
    # behaviour when CF_ENABLE_TAGS is off.
    is_system = models.BooleanField(default=False, db_index=True)

    objects = RepoTagsManager()

    def to_dict(self):
        return {
            "repo_tag_id": self.pk,
            "repo_id": self.repo_id,
            "tag_name": self.name,
            "tag_color": self.color,
            "is_system": self.is_system,
        }
