"""Corpus: shell commands built at run time (SL102)."""

import os
import shlex
import subprocess
import subprocess as sp
from os import system
from subprocess import run


def ping(host):
    os.system("ping -c 1 " + host)  # expect: SL102


def disk_usage(folder):
    return os.popen(f"du -sh {folder}").read()  # expect: SL102


def who_is(user):
    return subprocess.getoutput("id " + user)  # expect: SL102


def convert(name):
    subprocess.run(f"convert {name} out.png", shell=True)  # expect: SL102


def archive(folder):
    return subprocess.check_output("tar czf backup.tgz %s" % folder, shell=True)  # expect: SL102


def clone(url):
    subprocess.run(  # expect: SL102
        "git clone " + url,
        shell=True,
        check=True,
    )


def renamed_module(command):
    sp.Popen(command, shell=True)  # expect: SL102


def imported_function(command):
    system(command)  # expect: SL102


def imported_run(command):
    run(command, shell=True)  # expect: SL102


def stored_in_a_variable(command):
    launch = os.system
    launch(command)  # expect: SL102


def options_in_a_dictionary(command):
    options = {"shell": True}
    subprocess.run(command, **options)  # missed: SL102


def shell_started_by_hand(command):
    subprocess.run(["sh", "-c", command])  # missed: SL102


# ---- Safe code: nothing below is dangerous. ----


def clear_screen():
    os.system("clear")


def ping_safely(host):
    subprocess.run(["ping", "-c", "1", host], check=True)


def fixed_pipeline():
    subprocess.run("ls -l | wc -l", shell=True, check=True)


def fixed_in_two_parts():
    os.system("ls " + "-l")  # false-alarm: SL102


def quoted(host):
    os.system("ping -c 1 " + shlex.quote(host))  # false-alarm: SL102


def other_library(app, command):
    app.run(command, shell=True)


def fixed_command_in_a_variable():
    command = "ls -l"
    os.system(command)
