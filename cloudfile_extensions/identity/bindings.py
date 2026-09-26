"""Strict CE identity prebinding without email/employee-number account merging.

Trusted callers must authorize prebinding and supply the native coordinator and
durable audit adapter. This is not a public login/JIT endpoint or a new table.
"""

import hashlib
import json

from django.db import IntegrityError, transaction

from ..common.errors import ContractError
from ..common.http import trusted_https_url
from ..common.validation import identifier


def conflict():
    return ContractError("IDENTITY_CONFLICT", "Identity binding conflicts with an existing account", 409)


class IdentityBindings:
    @classmethod
    def native(cls, *, guard, audit):
        """Use CE's actual models/state lookup, never an always-active callback.

        Trusted runtime assembly still supplies coordinator/audit adapters; this
        factory does not enable OIDC, JIT or a public prebinding endpoint.
        """
        from seahub.profile.models import Profile
        from seahub.auth.models import SocialAuthUser
        from .accounts import NativeAccounts
        accounts = NativeAccounts(profiles=Profile)
        return cls(profiles=Profile, social_users=SocialAuthUser,
                   account_active=accounts.active_username, guard=guard, audit=audit)

    def __init__(self, *, profiles, social_users, account_active, guard, audit):
        if not all(callable(value) for value in (account_active, guard, audit)):
            raise ValueError("trusted identity coordinator and audit adapters are required")
        if profiles._default_manager.db != social_users._default_manager.db:
            raise ValueError("native identity models must share one transaction database")
        self.profiles = profiles
        self.social = social_users
        self.account_active = account_active
        self.guard = guard
        self.audit = audit
        self.database = profiles._default_manager.db

    @staticmethod
    def _identity(issuer, subject, user_id):
        trusted_https_url(issuer)
        identifier(subject)
        identifier(user_id, maximum=225)
        # CE provider has 32 characters; full issuer remains in checked metadata,
        # so even a digest collision cannot silently bind another issuer.
        provider = "cf_oidc_" + hashlib.sha256(issuer.encode()).hexdigest()[:24]
        return provider, {"issuer": issuer, "userId": user_id}

    def resolve(self, *, issuer, subject, user_id):
        provider, metadata = self._identity(issuer, subject, user_id)
        binding = self.social._default_manager.filter(provider=provider, uid=subject).first()
        if binding is None:
            return None
        self._check_binding(binding, provider, subject, metadata)
        profile = self.profiles._default_manager.filter(user=binding.username).first()
        if profile is None or profile.user != binding.username or profile.login_id != user_id:
            raise conflict()
        if not self.account_active(binding.username):
            raise ContractError("SUBJECT_DISABLED", "Account is disabled", 403)
        return binding.username

    @staticmethod
    def _check_binding(binding, provider, subject, metadata):
        try:
            stored = json.loads(binding.extra_data)
        except (TypeError, ValueError):
            raise conflict() from None
        if binding.provider != provider or binding.uid != subject or stored != metadata:
            raise conflict()

    def prebind(self, *, issuer, subject, user_id, username, actor, reason):
        provider, metadata = self._identity(issuer, subject, user_id)
        identifier(username)
        identifier(actor)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 512:
            raise ContractError("INVALID_REQUEST", "A bounded binding reason is required", 400)
        try:
            # Guard must serialize missing as well as existing native rows and
            # coordinate account suspension through the final transaction commit.
            with self.guard(user_id, provider, subject, username), transaction.atomic(using=self.database):
                if not self.account_active(username):
                    raise ContractError("SUBJECT_DISABLED", "Account is disabled", 403)
                profiles = self.profiles._default_manager.select_for_update()
                profile = profiles.filter(user=username).first()
                other = profiles.filter(login_id=user_id).first()
                if (profile is None or profile.user != username or
                        profile.login_id not in (None, "", user_id) or
                        (other is not None and (other.user != username or other.login_id != user_id))):
                    raise conflict()
                bindings = self.social._default_manager.select_for_update()
                existing = bindings.filter(provider=provider, uid=subject).first()
                if existing is not None:
                    self._check_binding(existing, provider, subject, metadata)
                    if existing.username != username:
                        raise conflict()
                if existing is not None and profile.login_id == user_id:
                    return username, False
                profile.login_id = user_id
                profile.save(using=self.database, update_fields=["login_id"])
                if existing is None:
                    # Do not use the CE add() helper which logs and swallows DB
                    # errors; uniqueness violations must roll back the profile.
                    bindings.create(username=username, provider=provider, uid=subject,
                                    extra_data=json.dumps(metadata, sort_keys=True))
                self.audit({"action": "identity.bound", "actor_user_id": actor,
                            "userId": user_id, "username": username, "reason": reason})
                return username, True
        except IntegrityError:
            raise conflict() from None
