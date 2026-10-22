# Small hand-written cases for the slicer tests. Not real application code.
import configparser
import sqlite3


def stored_in_config(param):
    bar = 'safe!'
    conf = configparser.ConfigParser()
    conf.add_section('s')
    conf.set('s', 'keyA', 'a-Value')
    conf.set('s', 'keyB', param)
    bar = conf.get('s', 'keyB')
    unrelated = 42
    sql = f"SELECT name FROM users WHERE password = '{bar}'"
    cur = sqlite3.connect(':memory:').cursor()
    cur.execute(sql)


def dead_branch(param):
    num = 106
    bar = "constant" if 7 * 18 + num > 200 else param
    noise = "not used"
    sql = "SELECT name FROM users WHERE password = ?"
    cur = sqlite3.connect(':memory:').cursor()
    cur.execute(sql, (bar,))
