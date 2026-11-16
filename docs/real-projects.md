# SecureLint on real projects

The [annotated corpus](../tests/corpus/README.md) was written while building
SecureLint, so it favours it. This page looks at code SecureLint was never
written for: four well-known open-source projects, at a fixed release. Every
finding was read in its code and sorted by hand.

Measured on 2026-11-15 with SecureLint 0.6.0 and Bandit 1.9.4, scanning the
package each project ships (not its tests), with all five rules.

## The projects

| Project | Release | Commit | Folder scanned | Python files |
|---------|---------|--------|----------------|-------------:|
| [Flask](https://github.com/pallets/flask) | 3.1.3 | `22d9247` | `src/flask` | 24 |
| [Requests](https://github.com/psf/requests) | v2.34.2 | `6e83187` | `src/requests` | 19 |
| [HTTPie](https://github.com/httpie/cli) | 3.2.4 | `2105caa` | `httpie` | 78 |
| [Jinja](https://github.com/pallets/jinja) | 3.1.6 | `1520688` | `src/jinja2` | 25 |

To repeat it:

```console
git clone --depth 1 --branch 3.1.3 https://github.com/pallets/flask.git
git clone --depth 1 --branch v2.34.2 https://github.com/psf/requests.git
git clone --depth 1 --branch 3.2.4 https://github.com/httpie/cli.git
git clone --depth 1 --branch 3.1.6 https://github.com/pallets/jinja.git
python benchmarks/real_projects.py flask/src/flask requests/src/requests cli/httpie jinja/src/jinja2
```

## Results

Each finding was put in one of three groups:

- **Real risk**: the code does something dangerous with data an attacker
  could control in some setups.
- **Intended**: the code is dangerous by design and the project relies on the
  data being trusted. Worth knowing, and worth a silencing comment with a
  reason in that project.
- **False alarm**: no outside data can reach it, or it is not the problem the
  rule describes.

| Project | SecureLint findings | real / intended / false | Bandit findings (same five kinds) | real / intended / false |
|---------|-------------:|------|------------:|------|
| Flask | 2 | 0 / 2 / 0 | 4 | 0 / 2 / 2 |
| Requests | 0 | - | 0 | - |
| HTTPie | 0 | - | 2 | 0 / 0 / 2 |
| Jinja | 4 | 2 / 1 / 1 | 14 | 2 / 1 / 11 |
| **Total** | **6** | **2 / 3 / 1** | **20** | **2 / 3 / 15** |

Both tools found the same two real risks and the same three intended cases.
SecureLint had 1 false alarm, Bandit 15.

## Every finding

### Found by both tools

| Where | Code | Verdict |
|-------|------|---------|
| Jinja `bccache.py:73` | `pickle.load(f)` on a bytecode cache file | **Real risk.** Anyone who can write to the cache (a shared folder, a shared memcached) can run code in the application. |
| Jinja `bccache.py:79` | `marshal.load(f)` on the same cache | **Real risk**, for the same reason. |
| Flask `cli.py:1031` | `eval(compile(...))` of the `PYTHONSTARTUP` file in `flask shell` | **Intended.** It does what Python's own shell does with the user's startup file. |
| Flask `config.py:209` | `exec(compile(...))` in `Config.from_pyfile` | **Intended.** A Python config file is code by design; it must never be a file someone else can edit. |
| Jinja `environment.py:1228` | `exec(code, namespace)` in `Template.from_code` | **Intended.** Running compiled templates is what a template engine does; its safety rests on where templates come from. |
| Jinja `debug.py:145` | `exec(code, globals, locals)` | **False alarm.** Jinja builds this code object itself, only to raise an error with a cleaner traceback. |

### Found only by Bandit

All 14 are Bandit's "hard-coded password" check (B105), and all are false
alarms:

| Where | Code | Why it is not a secret |
|-------|------|------------------------|
| Flask `app.py:183`, `184` | `"SECRET_KEY": None`, `"SECRET_KEY_FALLBACKS": None` | Empty defaults in the configuration. |
| HTTPie `sessions.py:144`, `280` | `'password': None` | An empty placeholder. |
| Jinja `compiler.py:1440` | `pass_arg == "environment"` | Not a secret: the name of an argument. |
| Jinja `lexer.py:639`, `765` | `token == "keyword"`, `token == "#bygroup"` | A *token* here is a piece of template text. |
| Jinja `parser.py`, 7 lines | `token_type == "sub"`, `"dot"`, `"lparen"`... | The same: the type of a template token. |

SecureLint's secret rule reports none of them: it ignores `None`, empty and
placeholder values, and it does not treat comparisons as secrets.

## What this does not show

- **Only false alarms can be counted here, not misses.** Nobody marked every
  dangerous line in these projects, so a problem neither tool reports stays
  unseen. The corpus is where misses are measured.
- **Four projects, all mature, well-reviewed libraries.** They have few
  problems to find; an application written in a hurry would give more
  findings, and other kinds of false alarms.
- **The sorting is one person's reading** of each finding, with the reason
  written next to it so it can be checked.
- **Bandit checks much more** than these five kinds (it also warned about
  `assert`, weak hashes and more in these projects). Those warnings are not
  counted here.
