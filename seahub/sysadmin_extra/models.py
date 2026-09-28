# Copyright (c) 2012-2016 Seafile Ltd.
from django.db import models
from django.utils import timezone

class UserLoginLogManager(models.Manager):
    def create_login_log(self, username, login_ip, login_success=True):
        l = super(UserLoginLogManager, self).create(username=username,
                login_ip=login_ip, login_success=login_success)
        l.save()
        return l

class UserLoginLog(models.Model):
    username = models.CharField(max_length=255, db_index=True)
    login_date = models.DateTimeField(default=timezone.now, db_index=True)
    login_ip = models.CharField(max_length=128)
    login_success = models.BooleanField(default=True)

    objects = UserLoginLogManager()

    class Meta:
        ordering = ['-login_date']
        indexes = [
            models.Index(fields=['login_date', 'id'], name='login_time_id_idx'),
            models.Index(fields=['username', 'login_date', 'id'], name='login_user_time_idx'),
        ]

########## signal handler
from django.dispatch import receiver
from seahub.auth.signals import user_logged_in, user_logged_in_failed
from seahub.utils.ip import get_remote_ip

@receiver(user_logged_in)
def create_login_log(sender, request, user, **kwargs):
    username = user.username
    login_ip = get_remote_ip(request)
    UserLoginLog.objects.create_login_log(username, login_ip)

@receiver(user_logged_in_failed)
def create_login_failed_log(sender, request, **kwargs):
    username = request.POST.get('login', '')
    login_ip = get_remote_ip(request)
    UserLoginLog.objects.create_login_log(username,
            login_ip, login_success=False)

# Login history is audit evidence. Account deletion must not erase it.
