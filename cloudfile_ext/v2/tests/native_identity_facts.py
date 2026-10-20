"""Native SQL-boundary fixture; no real database or RPC service is accessed."""
from copy import deepcopy


class NativeFacts:
    """Model CE's case-insensitive lookup while returning exact stored values."""
    def __init__(self):
        self.accounts, self.profiles, self.social = {}, [], []
        self.rows, self.snapshot = (), None
        self.created = []

    def get_autocommit(self): return True
    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def fetchall(self): return tuple(self.rows)
    def begin(self): self.snapshot = deepcopy((self.accounts, self.profiles, self.social))
    def commit(self): self.snapshot = None
    def rollback(self):
        if self.snapshot is not None:
            self.accounts, self.profiles, self.social = self.snapshot
            self.snapshot = None

    def create(self, username):
        username = username.lower()
        if any(name.lower() == username.lower() for name in self.accounts):
            raise AssertionError('RPC must never adopt an existing account')
        self.created.append(username)
        self.accounts[username] = 1

    def execute(self, sql, args=()):
        self.rows = ()
        sql = sql.replace("`", "")
        if sql.startswith('SELECT'):
            if '.profile_profile' in sql:
                if 'WHERE user=%s OR login_id=%s' in sql:
                    rows = [r for r in self.profiles if r[0].lower() == args[0].lower() or r[1].lower() == args[1].lower()]
                elif 'WHERE login_id=%s' in sql:
                    rows = [r for r in self.profiles if r[1].lower() == args[0].lower()]
                else:
                    rows = [r for r in self.profiles if r[0].lower() == args[0].lower()]
                self.rows = rows
            elif '.EmailUser' in sql:
                rows = [(name, active) for name, active in self.accounts.items() if name.lower() == args[0].lower()]
                self.rows = rows if 'email,is_active' in sql else [(r[0],) for r in rows]
            elif '.social_auth_usersocialauth' in sql:
                self.rows = [r if "extra_data" in sql else r[:3] for r in self.social if r[1:3] == args]
            else:
                raise AssertionError(sql)
        elif sql.startswith('INSERT INTO'):
            if '.EmailUser' in sql:
                self.create(args[0])
            elif '.profile_profile' in sql:
                self.profiles.append(tuple(args[:2]))
            elif '.social_auth_usersocialauth' in sql:
                self.social.append(tuple(args))
            else:
                raise AssertionError(sql)
        else:
            raise AssertionError(sql)
