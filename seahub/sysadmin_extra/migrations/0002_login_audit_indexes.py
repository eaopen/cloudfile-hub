from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('sysadmin_extra', '0001_initial')]

    operations = [
        migrations.AddIndex(
            model_name='userloginlog',
            index=models.Index(fields=['login_date', 'id'], name='login_time_id_idx'),
        ),
        migrations.AddIndex(
            model_name='userloginlog',
            index=models.Index(fields=['username', 'login_date', 'id'], name='login_user_time_idx'),
        ),
    ]
