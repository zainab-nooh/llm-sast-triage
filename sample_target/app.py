"""A tiny deliberately vulnerable file for practice. Do not use this code in a real project."""
import hashlib
import subprocess

DB_PASSWORD = "hunter2"   # hard-coded secret (real finding)


def find_user_unsafe(cur, name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(query)                       # real SQL injection
    return cur.fetchall()


def find_user_safe(cur, name):
    if not name.isalnum():
        raise ValueError("bad name")
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))   # safe, uses placeholders
    return cur.fetchall()


def build_and_run(cur, table_hint):
    q = "SELECT * FROM items WHERE kind = '%s'" % "fixed"
    cur.execute(q)                           # flagged, but the value is a constant (false positive)
    return cur.fetchall()


def ping(host):
    subprocess.run("ping -c 1 " + host, shell=True)   # real command injection


def list_files():
    subprocess.run("ls -l", shell=True)      # flagged, but the command is constant (false positive)


def fingerprint(data):
    return hashlib.md5(data).hexdigest()     # weak hash, non-security use (debatable)
