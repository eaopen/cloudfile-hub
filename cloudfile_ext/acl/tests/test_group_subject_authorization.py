"""Roles/departments stay as ACL subjects; authorization matches memberships."""
from cloudfile_ext.acl import resolver


def rule(kind, subject, permission):
    return dict(path='/docs', subject_type=kind, subject=str(subject),
                permission=permission, inherit=True)


def test_department_rule_matches_member_and_not_unrelated_user():
    # A single department ACL works for every member without per-user rows.
    rules = [rule('dept', 2001, 'r')]
    for username in ('member-one', 'member-two'):
        assert resolver.resolve(rules, resolver.subject_set(username, dept_ids=[2001]), '/docs/x', 'rw') == 'r'
    assert resolver.resolve(rules, resolver.subject_set('other', dept_ids=[2002]), '/docs/x', 'rw') == 'rw'


def test_role_rule_changes_with_current_user_membership():
    rules = [rule('group', 42, 'rw')]
    assert resolver.resolve(rules, resolver.subject_set('member', group_ids=[42]), '/docs/x', 'r') == 'rw'
    assert resolver.resolve(rules, resolver.subject_set('member'), '/docs/x', 'r') == 'r'
    assert resolver.resolve([], resolver.subject_set('member', group_ids=[42]), '/docs/x', 'r') == 'r'


def test_department_rule_matches_ancestor_and_requires_library_access():
    rules = [rule('dept', 2001, 'r')]
    subjects = resolver.subject_set('member', dept_ids=[2002, 2001])
    assert resolver.resolve(rules, subjects, '/docs/x', 'rw') == 'r'
    assert resolver.resolve(rules, subjects, '/docs/x', None) is None


def test_modern_subject_keys_match_business_roles_and_organization_ancestors():
    from cloudfile_extensions.authorization.directory_management import subject_keys
    subject = dict(userId='member', organizations=[dict(namespace='directory', external_id='2002')],
                   organization_ancestors=[dict(namespace='directory', external_id='2001')],
                   roles=[dict(namespace='role', external_id='2001')])
    # Same business ID in role and department must remain two distinct subjects.
    assert subject_keys(subject, 'etech') == {
        ('user', 'etech', 'user', 'member'), ('dept', 'etech', 'directory', '2002'),
        ('dept', 'etech', 'directory', '2001'), ('group', 'etech', 'role', '2001')}
