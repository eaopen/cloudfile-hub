from django.db import migrations, models


def preserve_auto_read_grants(apps, schema_editor):
    for model_name in ('ExtraSharePermission', 'ExtraGroupsSharePermission'):
        model = apps.get_model('share', model_name)
        model.objects.filter(auto_granted_access=True).update(auto_granted_permission='r')


class Migration(migrations.Migration):
    dependencies = [('share', '0004_library_admin_auto_read')]

    operations = [
        migrations.RenameField(
            model_name='extrasharepermission',
            old_name='auto_granted_read',
            new_name='auto_granted_access',
        ),
        migrations.RenameField(
            model_name='extragroupssharepermission',
            old_name='auto_granted_read',
            new_name='auto_granted_access',
        ),
        migrations.AddField(
            model_name='extrasharepermission',
            name='auto_granted_permission',
            field=models.CharField(blank=True, default='', max_length=15),
        ),
        migrations.AddField(
            model_name='extrasharepermission',
            name='auto_grant_previous_permission',
            field=models.CharField(blank=True, default='', max_length=15),
        ),
        migrations.AddField(
            model_name='extragroupssharepermission',
            name='auto_granted_permission',
            field=models.CharField(blank=True, default='', max_length=15),
        ),
        migrations.AddField(
            model_name='extragroupssharepermission',
            name='auto_grant_previous_permission',
            field=models.CharField(blank=True, default='', max_length=15),
        ),
        migrations.RunPython(preserve_auto_read_grants, migrations.RunPython.noop),
    ]
