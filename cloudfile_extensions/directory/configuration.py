"""One configured membership writer per deployment; no request-side switch."""


def membership_mode(configured):
    mode = configured.get("membership_mode", "snapshot") if isinstance(configured, dict) else "snapshot"
    if mode not in ("snapshot", "subject_ttl"):
        raise ValueError("invalid directory membership mode")
    return mode


def subject_ttl(configured):
    value = configured.get("subject_ttl", 1800)
    if type(value) is not int or not 60 <= value <= 1800:
        raise ValueError("subject TTL must be between 60 and 1800 seconds")
    return value


def uses_subject_projection():
    from django.conf import settings
    if getattr(settings, "configured", True) is False:
        return False
    return membership_mode(getattr(settings, "CLOUDFILE_POLICY_CONFIG", None)) == "subject_ttl"
