#!/usr/bin/env python3
"""Read-only, credential-redacting P0-C directory-page contract/latency probe.

Run from a host with access to the existing EAP or Hub Dev endpoint. This tool
never creates directories or modifies data; cases must point at existing data.
All paths, tokens, filenames, and repository IDs are excluded from output.
"""
import argparse
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def parse_case(text):
    label, sep, path = text.partition('=')
    if not sep or not label or not path.startswith('/'):
        raise argparse.ArgumentTypeError('case must be LABEL=/existing/directory')
    return label, path


def read_page(base_url, repo_id, path, start, limit, revision, mode, timeout):
    prefix = 'eap/cloudDrive/libraries' if mode == 'eap' else 'api/v2.1/repos'
    suffix = 'items-page' if mode == 'eap' else 'dir/'
    parameters = {'p': path, 'start': str(start), 'limit': str(limit)}
    if revision:
        parameters['ifDirId' if mode == 'eap' else 'if_dir_id'] = revision
    url = (base_url.rstrip('/') + '/' + prefix + '/' +
           urllib.parse.quote(repo_id, safe='') + '/' + suffix + '?' +
           urllib.parse.urlencode(parameters))
    headers = {'Accept': 'application/json'}
    cookie = os.environ.get('CLOUDFILE_P0C_COOKIE', '')
    if cookie:
        headers['Cookie'] = cookie
    if mode == 'eap':
        token = os.environ.get('CLOUDFILE_P0C_EAP_BEARER', '')
        if token:
            headers['Authorization'] = 'Bearer ' + token
        headers['X-Request-Scene'] = 'webDisk'
    else:
        token = os.environ.get('CLOUDFILE_P0C_HUB_TOKEN', '')
        if token:
            headers['Authorization'] = 'Token ' + token
    if not cookie and not token:
        raise ValueError('Set an authentication token or CLOUDFILE_P0C_COOKIE in the environment')

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as response:
            headers_ms = (time.perf_counter() - started) * 1000
            status = response.status
            data = response.read(5 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        raise ValueError('HTTP %s (check authorization/version, no response data logged)' % exc.code) from None
    elapsed_ms = (time.perf_counter() - started) * 1000
    if len(data) > 5 * 1024 * 1024:
        raise ValueError('response exceeds 5 MiB inspection budget')
    if status != 200:
        raise ValueError('unexpected HTTP status %d' % status)
    try:
        body = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        raise ValueError('response is not valid JSON') from None
    if mode == 'eap':
        if body.get('code') != 0 or not isinstance(body.get('data'), dict):
            raise ValueError('EAP business status is not success')
        payload = body['data']
        entries = payload.get('items')
        more = payload.get('hasMore')
        next_start = payload.get('nextStart')
        dir_id = payload.get('dirId')
    else:
        if body.get('acl_enforced') is not True:
            raise ValueError('Hub did not declare ACL-enforced directory page')
        entries = body.get('dirent_list')
        more = body.get('has_more')
        next_start = body.get('next_start')
        dir_id = body.get('dir_id')
    if not isinstance(entries, list) or len(entries) > limit or not isinstance(more, bool):
        raise ValueError('invalid page entries/has-more contract')
    if not isinstance(dir_id, str) or len(dir_id) != 40:
        raise ValueError('missing or invalid directory-object revision')
    if more and (type(next_start) is not int or next_start <= start):
        raise ValueError('non-advancing directory cursor')
    if not more and next_start is not None:
        raise ValueError('terminal page has a non-null cursor')
    for entry in entries:
        if not isinstance(entry, dict) or entry.get('permission') not in ('r', 'rw'):
            raise ValueError('directory entry has no valid effective permission')
    return dict(first_byte_ms=round(headers_ms, 2), total_ms=round(elapsed_ms, 2),
                visible=len(entries), has_more=more, next_start=next_start, dir_id=dir_id)


def probe(args, label, path):
    trials = []
    for _ in range(args.repeats):
        cursor = 0
        revision = None
        pages = []
        for _ in range(args.max_pages):
            item = read_page(args.base_url, args.repo_id, path, cursor, args.limit,
                             revision, args.mode, args.timeout)
            if revision is not None and item['dir_id'] != revision:
                raise ValueError('directory revision changed between pages')
            revision = item['dir_id']
            pages.append(item)
            if not item['has_more']:
                break
            cursor = item['next_start']
        trials.append(pages)
    return dict(label=label, mode=args.mode, repeats=args.repeats,
                max_pages=args.max_pages, limit=args.limit,
                median_first_page_ms=round(statistics.median(p[0]['total_ms'] for p in trials), 2),
                median_first_byte_ms=round(statistics.median(p[0]['first_byte_ms'] for p in trials), 2),
                max_first_page_ms=round(max(p[0]['total_ms'] for p in trials), 2),
                pages_per_trial=[len(p) for p in trials],
                visible_per_trial=[sum(item['visible'] for item in p) for p in trials],
                next_page_exists=[bool(p[-1]['has_more']) for p in trials])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True,
                        help='EAP admin-api base URL or Hub base URL, depending on mode')
    parser.add_argument('--repo-id', required=True)
    parser.add_argument('--mode', choices=('eap', 'hub'), default='eap')
    parser.add_argument('--case', type=parse_case, action='append', required=True,
                        help='LABEL=/existing/directory (repeat for 50/500/5000 known-size directories)')
    parser.add_argument('--limit', type=int, default=50)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--max-pages', type=int, default=2)
    parser.add_argument('--timeout', type=float, default=15)
    args = parser.parse_args()
    if not 1 <= args.limit <= 200 or not 1 <= args.repeats <= 10 or not 1 <= args.max_pages <= 20:
        parser.error('limit must be 1..200, repeats 1..10, max-pages 1..20')
    try:
        results = [probe(args, label, path) for label, path in args.case]
    except (ValueError, TimeoutError, OSError) as exc:
        print('P0-C probe FAILED: %s' % exc, file=sys.stderr)
        return 1
    print(json.dumps({'status': 'contract_ok', 'note': 'HTTP measurements are real only on the executing host',
                      'cases': results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
