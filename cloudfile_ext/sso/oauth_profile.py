"""Optional OAuth profile metadata must never replace the stable subject binding."""

import logging

logger = logging.getLogger(__name__)


def update_optional_contact_email(profile, contact_email):
    """Skip a shared mailbox instead of merging users or failing their login.

    Seahub keeps contact_email unique even when the identity provider permits
    duplicate mailboxes. The provider/sub binding and employee login_id remain
    authoritative; neither an existing mailbox owner nor a concurrent update
    may redirect authentication to a different account.
    """
    from django.db import IntegrityError, transaction

    value = str(contact_email or '').strip().lower()
    if not value or getattr(profile, 'is_manually_set_contact_email', False):
        return False
    original = profile.contact_email
    if str(original or '').lower() == value:
        return True

    def assigned_elsewhere():
        return type(profile).objects.filter(
            contact_email__iexact=value).exclude(user=profile.user).exists()

    if assigned_elsewhere():
        logger.warning('Skipped shared OAuth contact email; subject binding retained')
        return False

    profile.contact_email = value
    try:
        # A savepoint lets us inspect a concurrent mailbox conflict after the
        # failed save without leaving the request transaction unusable.
        with transaction.atomic(using=profile._state.db):
            profile.save()
    except IntegrityError:
        profile.contact_email = original
        if not assigned_elsewhere():
            # Do not suppress unrelated unique constraints, such as login_id.
            raise
        logger.warning('Skipped concurrent OAuth contact email conflict; subject binding retained')
        return False
    return True
