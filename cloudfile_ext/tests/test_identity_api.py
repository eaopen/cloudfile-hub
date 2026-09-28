from cloudfile_ext.identity import unique_identity, AmbiguousSubject


def test_external_id_resolution_requires_one_native_identity():
    assert unique_identity([]) is None
    assert unique_identity(['opaque@auth.local', 'opaque@auth.local']) == 'opaque@auth.local'
    try:
        unique_identity(['first@auth.local', 'second@auth.local'])
    except AmbiguousSubject:
        pass
    else:
        raise AssertionError('ambiguous provider bindings must be rejected')
