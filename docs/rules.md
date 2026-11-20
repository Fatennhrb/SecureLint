> [← Back to SecureLint overview](../README.md) · [Full original README snapshot](archive/README-original-2026-11-18.md)

> Implemented code security rules, confidence levels and current analysis boundaries.

## Rules

| ID | Severity | What it reports |
|----|----------|-----------------|
| SL001 | Low | A `securelint:` comment that silences nothing. |
| SL101 | High | `eval()` or `exec()` called with a value built at run time. A fixed string such as `eval("2 + 2")` is not reported. |
| SL102 | High | A shell command built at run time: `os.system()`, `os.popen()`, `subprocess.getoutput()`, a `subprocess` call with `shell=True` (also through a variable that is certainly `True`), or a shell started by hand: `subprocess.run(["sh", "-c", command])`, also `bash -lc` and `cmd /c`. A fixed command, or a list of arguments without `shell=True`, is not reported. |
| SL103 | High | Data loaded with a format that can run code: `pickle`, `dill` or `marshal` loading, `pandas.read_pickle()`, and `yaml.load()` without a safe loader. `yaml.safe_load()` and JSON are not reported. |
| SL104 | Medium | A password or key written directly in the code, such as `password = "hunter2"`, `connect(password="hunter2")` or `{"api_key": "sk-live-123"}`. The rule reads the name, so `password_field = "password"`, empty strings and placeholders such as `"<password>"` are not reported. A password inside an address, such as `"postgres://app:hunter2@db/app"`, is reported under any name. The secret itself is never printed in the report. |
| SL105 | High | An SQL query with values put into its text, passed to `execute()`, `executemany()`, `executescript()`, `raw()`, `pandas.read_sql()` or `pandas.read_sql_query()`: `"..." + name`, an f-string, `"..." % name` or `"...".format(name)`. A fixed query with the values passed separately, such as `execute("... WHERE id = ?", (user_id,))`, is not reported. |
| SL201 | From Trivy | A dependency with a known vulnerability, read from a Trivy report (see [Checking dependencies and Dockerfiles with Trivy](dependencies-and-trivy.md#checking-dependencies-and-dockerfiles-with-trivy)). Critical, high, medium and low come from Trivy; a vulnerability Trivy has no severity for yet counts as medium. |
| SL202 | From Trivy | An unsafe setting in a Dockerfile or another configuration file, read from a Trivy report: for example, a container that runs as `root`. Medium confidence: the setting may be on purpose. |

Rules follow imports, so a function is recognised under any name the file gives
it: `import subprocess as sp`, `from os import system` and
`from os import system as sh` are all understood.

Rules also look through a variable to the value it was given, inside one
function:

```python
query = f"SELECT * FROM users WHERE name = '{name}'"
cursor.execute(query)  # reported: the query is built from a value

command = "ls -l"
os.system(command)  # not reported: the command is fixed
```

A function kept in a variable is followed the same way: after
`run = os.system`, the call `run(command)` is checked as `os.system(command)`.

This is done only when the variable is assigned exactly once. A variable
assigned twice, changed with `+=`, or received as a parameter has no single
value, and is treated as before.

SQL queries are also read when they are built in steps, or by a function in
the same file. Both of these are reported:

```python
query = "SELECT * FROM users"
query += f" WHERE name = '{name}'"
cursor.execute(query)  # every "=" and "+=" of query is read


def find_user(name):
    return f"SELECT * FROM users WHERE name = '{name}'"


cursor.execute(find_user(name))  # what find_user returns is read
```

A variable is read this way only when every value it gets comes from `=` or
`+=`; a loop variable or a parameter among them stops it. A function is read
only when it is defined once with `def`, has a single `return`, no decorator,
and is not a generator or `async def`. A function imported from another file
is not read.

A value set once at the top of a file is known inside every function of that
file, and fixed pieces put together are still fixed. None of these is reported:

```python
TABLE = "users"


def find(cursor, ids):
    marks = ", ".join("?" for _ in ids)  # only "?" and ", ", however many
    cursor.execute(f"SELECT * FROM {TABLE} WHERE id IN ({marks})", ids)


os.system("ls " + "-l")
```

### Confidence

Every finding has a confidence: how sure SecureLint is that the problem is
real. It is shown in the JSON and HTML reports.

Most findings are **medium**: the value is not fixed, but SecureLint cannot see
where it comes from. A finding becomes **high** when the value is followed back
to a place where outside data enters the program: a web request
(`request.args`, `request.form`, `request.GET`...), `input()`, `sys.argv` or
`sys.stdin`. The message then says where:

```python
name = request.args["name"]
query = f"SELECT * FROM users WHERE name = '{name}'"
cursor.execute(query)
# ... Here the value comes from request.args on line 1.
```
