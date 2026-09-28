from django.db import migrations, models
from django.db.models import Count


def deduplicate_markers(apps, schema_editor):
    # Existing AdminShares paths may have created repeated identical markers.
    # Keep the oldest marker; duplicate rows do not represent distinct grants.
    for model_name, subject in (('ExtraSharePermission', 'share_to'),
                                ('ExtraGroupsSharePermission', 'group_id')):
        model = apps.get_model('share', model_name)
        duplicates = (model.objects.using(schema_editor.connection.alias)
                      .values('repo_id', subject).annotate(total=Count('id')).filter(total__gt=1))
        for item in duplicates.iterator():
            matching = model.objects.using(schema_editor.connection.alias).filter(
                repo_id=item['repo_id'], **{subject: item[subject]}).order_by('id')
            keep = (matching.filter(permission='admin').values_list('id', flat=True).first()
                    or matching.values_list('id', flat=True).first())
            matching.exclude(id=keep).delete()


class Migration(migrations.Migration):
    dependencies = [('share', '0002_fileshare_description_uploadlinkshare_description')]

    operations = [
        migrations.RunPython(deduplicate_markers, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name='extrasharepermission',
            constraint=models.UniqueConstraint(fields=('repo_id', 'share_to'), name='unique_library_user_admin')),
        migrations.AddConstraint(
            model_name='extragroupssharepermission',
            constraint=models.UniqueConstraint(fields=('repo_id', 'group_id'), name='unique_library_group_admin')),
    ]
