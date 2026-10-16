"""Generic login labels are checked against UID authority, never adopted as keys."""
import pytest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.external import (
    assert_login_identity, directory_login_name, new_native_username,
)


def subject(**attributes):
    return dict(userId="stable-uid", attributes=attributes)


def test_generic_login_labels_allow_unicode_and_email_without_naming_native_accounts():
    for name in ("研发员工", "employee@example.test", "E-001"):
        source = subject(login_name=name)
        assert directory_login_name(source) == name
        native = new_native_username(source)
        assert native.endswith("@auth.local")
        assert len(native.split("@")[0]) == 32
        assert native != name + "@auth.local"
        assert_login_identity(dict(userId="stable-uid", login_name=name), source)


def test_renamed_login_keeps_the_stable_uid_and_recycled_label_cannot_prove_identity():
    identity = dict(userId="stable-uid", login_name="new-name")
    assert_login_identity(identity, subject(login_name="new-name"))
    for changed in (dict(userId="different-uid", attributes=dict(login_name="new-name")),
                    subject(login_name="old-name"), subject()):
        with pytest.raises(ContractError):
            assert_login_identity(identity, changed)


@pytest.mark.parametrize("attributes", [dict(login_name=""), dict(login_name=" leading"),
    dict(login_name="a\nb"), dict(login_name="a\x00b"), dict(login_name=1),
    dict(login_name="a", employee_no="b")])
def test_ambiguous_or_malformed_labels_fail_closed(attributes):
    with pytest.raises(ContractError):
        directory_login_name(subject(**attributes))


def test_legacy_employee_source_retains_its_deployed_account_convention():
    assert new_native_username(subject(employee_no="E-001")) == "E-001@auth.local"
    assert directory_login_name(subject(employee_no="E-001", login_name="E-001")) == "E-001"
    for employee in ("cfadmin", "name@example.test", "../name"):
        with pytest.raises(ContractError):
            new_native_username(subject(employee_no=employee))
