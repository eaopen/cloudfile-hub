from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('share', '0003_unique_library_administrators')]

    operations = [
        migrations.AddField(
            model_name='extrasharepermission',
            name='auto_granted_read',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='extragroupssharepermission',
            name='auto_granted_read',
            field=models.BooleanField(default=False),
        ),
    ]
