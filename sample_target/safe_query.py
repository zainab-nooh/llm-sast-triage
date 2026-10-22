"""Practice file: the scanner flags this, but the value is a constant, so it is a false positive."""


def get_items(cur):
    q = "SELECT * FROM items WHERE kind = '%s'" % "fixed"
    cur.execute(q)
    return cur.fetchall()
