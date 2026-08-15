# CloudFile P2-07: add the system/user classification marker to repo tags.
#
# The docker deploy also applies this column through bootstrap.py's
# apply_tag_schema_compatibility() so an existing CE deployment adopting
# CloudFile gets it without running this migration; this migration exists for
# the Django test runner and for deployments that do run manage.py migrate.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('repo_tags', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='repotags',
            name='is_system',
            field=models.BooleanField(db_index=True, default=False),
        ),
    ]
