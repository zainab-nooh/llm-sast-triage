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


def branch_decides(param):
    num = 86
    if 7 * 42 - num > 200:
        bar = 'This_should_always_happen'
    else:
        bar = param
    noise = "not used"
    eval(bar)


def case_decides(param):
    possible = "ABC"
    guess = possible[1]
    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case _:
            bar = param
    noise = "not used"
    eval(bar)




def import_alert(param):
    bar = param
    import xml.sax
    noise = "not used"
    parser = xml.sax.make_parser()
    xml.sax.parseString(bar, parser)        
