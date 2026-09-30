"""Scope, failure and permission tests for non-recursive search."""
import stat
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from cloudfile_ext.search.bounded import SearchFailure, query_page
from cloudfile_ext.search.backends.meilisearch import MeilisearchError
REPO = '11111111-1111-4111-8111-111111111111'


def entry(name='drawing.txt', directory=False):
    return SimpleNamespace(obj_name=name, mode=stat.S_IFDIR if directory else stat.S_IFREG, size=42, mtime=100)


def invoke(**overrides):
    args = dict(repo_id=REPO, q='drawing', path='/a', limit=2, offset=0, provider=None,
        client=Mock(), list_directory=Mock(return_value=[]), resolve_item=Mock(return_value=entry()),
        can_read=Mock(return_value=True))
    args['client']._call.return_value = {'hits': []}
    args.update(overrides)
    return query_page(**args), args


def test_meili_filters_scope_and_unifies_names_tags_without_scan():
    client=Mock();client._call.return_value={'hits':[{'repo_id':REPO,'path':'/a/drawing.txt','tags':['drawing'],
        '_formatted':{'tags':['<em>drawing</em>']}}]}
    result,args=invoke(client=client)
    payload=client._call.call_args.args[2]
    assert payload['attributesToSearchOn']==['name','tags']
    assert 'dirs IN ["/a"]' in payload['filter'] and payload['matchingStrategy']=='all'
    args['list_directory'].assert_not_called()
    assert result['data'][0]['matched_tags']==['drawing']
    assert result['provider']=='meilisearch' and result['fallback'] is False


def test_empty_index_result_does_not_trigger_fallback():
    result,args=invoke()
    assert result['data']==[] and result['provider']=='meilisearch'
    args['list_directory'].assert_not_called()


def test_backend_fault_reads_one_directory_page_without_children():
    client=Mock();client._call.side_effect=MeilisearchError('offline')
    listing=Mock(return_value=[entry('drawing.txt'),entry('drawing-folder',True),entry('other.txt')])
    result,args=invoke(client=client,list_directory=listing)
    listing.assert_called_once_with('/a',0,500)
    assert [x['path'] for x in result['data']]==['/a/drawing.txt']
    assert result['scope']=='directory' and result['fallback'] is True
    args['resolve_item'].assert_called_once_with('/a/drawing.txt')


def test_native_page_resumes_before_unreturned_matches():
    result,_=invoke(client=None,list_directory=Mock(return_value=[entry('drawing1'),entry('drawing2'),entry('drawing3')]))
    assert len(result['data'])==2 and result['next_offset']==2


def test_large_directory_continuation_reads_one_page_and_is_not_silently_cut_off():
    listing = Mock(return_value=[entry('drawing')] + [entry('other')] * 499)
    result, _ = invoke(provider='native', client=None, offset=10000, list_directory=listing)
    listing.assert_called_once_with('/a', 10000, 500)
    assert result['next_offset'] == 10500


def test_index_cursor_does_not_switch_provider_on_fault():
    client=Mock();client._call.side_effect=MeilisearchError('offline');listing=Mock()
    with pytest.raises(SearchFailure): invoke(client=client,provider='meilisearch',list_directory=listing)
    listing.assert_not_called()


def test_index_cursor_does_not_switch_when_provider_configuration_changes():
    listing = Mock()
    with pytest.raises(SearchFailure):
        invoke(client=None, provider='meilisearch', list_directory=listing)
    listing.assert_not_called()


def test_trailing_slash_and_literal_characters_filter_the_same_directory():
    client = Mock(); client._call.return_value = {'hits': []}
    path = '/中文/%2F+_"'
    result, _ = invoke(client=client, path=path + '/')
    import json
    assert result['path'] == path
    assert 'dirs IN ' + json.dumps([path], ensure_ascii=False) in client._call.call_args.args[2]['filter']


def test_denied_stale_and_sibling_prefix_candidates_are_not_returned():
    client=Mock();client._call.return_value={'hits':[
        {'repo_id':REPO,'path':'/a/hidden/x.txt'},{'repo_id':REPO,'path':'/ab/x.txt'}]}
    result,args=invoke(client=client,can_read=lambda p:p!='/a/hidden')
    assert result['data']==[];args['resolve_item'].assert_not_called()
    client._call.return_value={'hits':[{'repo_id':REPO,'path':'/a/deleted.txt'}]}
    result,_=invoke(client=client,resolve_item=Mock(return_value=None))
    assert result['data']==[]


def test_denied_scope_and_wrong_library_fail_without_fallback():
    client=Mock();listing=Mock()
    with pytest.raises(SearchFailure) as failure: invoke(client=client,list_directory=listing,can_read=lambda _:False)
    assert failure.value.status==403
    client._call.assert_not_called();listing.assert_not_called()
    client._call.return_value={'hits':[{'repo_id':'other','path':'/a/x.txt'}]}
    with pytest.raises(SearchFailure): invoke(client=client,list_directory=listing)
    listing.assert_not_called()
