"""Statement-local tag SELECT deadlines; never change pooled session settings."""
from contextlib import contextmanager
import time


class TagQueryTimeout(TimeoutError):
    pass


def remaining_ms(deadline):
    # Zero disables the database limit, so an exhausted budget must not execute.
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining < 1:
        raise TagQueryTimeout('directory tag query budget exhausted')
    return remaining


@contextmanager
def query_budget(connection, deadline):
    if connection.vendor != 'mysql':
        # An unavailable limiter degrades display metadata, never runs unbounded.
        raise ValueError('bounded directory tags require MySQL or MariaDB')
    connection.ensure_connection()
    mariadb = connection.mysql_is_mariadb

    def bounded_execute(execute, sql, params, many, context):
        statement = sql.lstrip()
        if many or not statement.upper().startswith('SELECT '):
            raise ValueError('tag budget only permits read-only SELECT')
        milliseconds = remaining_ms(deadline)
        if mariadb:
            # MariaDB uses seconds; SET STATEMENT restores the session value
            # even on interruption. MySQL's hint is milliseconds, not seconds.
            statement = 'SET STATEMENT max_statement_time=%.3f FOR %s' % (
                milliseconds / 1000, statement)
        else:
            statement = 'SELECT /*+ MAX_EXECUTION_TIME(%d) */ %s' % (
                milliseconds, statement[len('SELECT '):])
        return execute(statement, params, many, context)

    with connection.execute_wrapper(bounded_execute):
        yield
