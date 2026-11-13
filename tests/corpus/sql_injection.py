"""Corpus: SQL queries with values put into their text (SL105)."""

import pandas
from sqlalchemy import text

TABLE = "users"


def find_by_name(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")  # expect: SL105


def find_by_id(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # expect: SL105


def delete(cursor, user_id):
    cursor.execute("DELETE FROM users WHERE id = %s" % user_id)  # expect: SL105


def search(cursor, column, value):
    cursor.execute("SELECT * FROM users WHERE {} = '{}'".format(column, value))  # expect: SL105


def change_email(cursor, user_id, email):
    cursor.execute(  # expect: SL105
        "UPDATE users SET email = '" + email + "' "
        "WHERE id = " + str(user_id)
    )


def find_many(cursor, ids):
    cursor.execute("SELECT * FROM users WHERE id IN (" + ",".join(ids) + ")")  # expect: SL105


def reset(connection, table):
    connection.executescript(f"DROP TABLE {table}; CREATE TABLE {table} (id INTEGER)")  # expect: SL105


def sorted_users(session, column):
    return session.execute(text(f"SELECT * FROM users ORDER BY {column}"))  # expect: SL105


def django_raw(user_id):
    return User.objects.raw(f"SELECT * FROM auth_user WHERE id = {user_id}")  # expect: SL105


def built_on_another_line(cursor, name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)  # expect: SL105


def with_pandas(connection, city):
    return pandas.read_sql(f"SELECT * FROM users WHERE city = '{city}'", connection)  # missed: SL105


# ---- Safe code: nothing below is dangerous. ----


def find_by_name_safely(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))


def find_by_id_safely(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def sorted_users_safely(session, user_id):
    return session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})


def everyone(cursor):
    cursor.execute("SELECT * FROM users ORDER BY name")


def own_table_name(cursor, user_id):
    cursor.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (user_id,))


def one_mark_per_value(cursor, ids):
    marks = ", ".join("?" for _ in ids)
    cursor.execute(f"SELECT * FROM users WHERE id IN ({marks})", ids)


def not_a_database(executor, number):
    executor.execute(f"job-{number}")


def only_logged(logger, user_id):
    logger.info(f"SELECT * FROM users WHERE id = {user_id}")


def fixed_query_in_a_variable(cursor):
    query = "SELECT * FROM users ORDER BY name"
    cursor.execute(query)
