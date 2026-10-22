"""Filter native CE library results with the existing V2 authority."""
from functools import wraps


def web_list(kind):
    if kind != 'libraries':
        raise ValueError('native library list required')

    def decorate(view):
        @wraps(view)
        def guarded(self, request, *args, **kwargs):
            from cloudfile_ext.v2.acl_runtime import Authority
            from cloudfile_ext.v2.acl_http import failure
            response = view(self, request, *args, **kwargs)
            if response.status_code != 200:
                return response
            try:
                authority = Authority(request.user.username)
                visible = []
                for entry in response.data['repos']:
                    decision = authority.effective(entry['repo_id'], '/')
                    if decision.can_read:
                        visible.append(dict(entry, permission=decision.permission))
                response.data = dict(response.data, repos=visible)
                response['Cache-Control'] = 'no-store'
                return response
            except Exception as error:
                return failure(error)
        return guarded
    return decorate
