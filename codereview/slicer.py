"""Step 3: cut out only the code the model needs (context levels 1 to 3).

Level 1: the enclosing function.
Level 2: the sink statement, the assignments it depends on, and the guard statements (if/assert) that
         mention those variables. Uses the scanner trace too, when there is one.
Level 3: level 2 plus the bodies of helper functions defined in the same file and called in the slice.
If the file cannot be parsed or no function encloses the line, fall back to a window of nearby lines.
"""
import ast
from pathlib import Path
from typing import List, Optional, Set

from .models import Context, Finding

WINDOW = 10

# Reads a file from a file system path , handeling decoding errors by replacing invalid characters with a placeholder. Returns the file content as a list of lines.
def _read(root: str, rel: str) -> List[str]:
    return (Path(root) / rel).read_text(errors="replace").splitlines()


# Traverses the Abstract Syntax Tree to find and return all synchronous (def) and asynchronous (asynch def) function defenitions within a file
def _functions(tree: ast.AST):
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


# Identifys which specific function wraps the targeted line number. If multiple nested functions match, It correctly idenytifies the "deepest" or most immediate enclosing function.
def enclosing_function(tree: ast.AST, line: int):
    best = None
    for fn in _functions(tree):
        if fn.lineno <= line <= (fn.end_lineno or fn.lineno):
            if best is None or fn.lineno > best.lineno:
                best = fn
    return best


# Extracts all variable and argument names used inside a given code block or statement
def _names(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


# Finds all individual execution statements (like loops, conditions, or assignments) inside a function, filtering out the function definition header itself.
def _stmts(fn) -> List[ast.stmt]:
    return [n for n in ast.walk(fn) if isinstance(n, ast.stmt) and n is not fn]



#  Finds the exact statement on the targeted line. If multiple statements span that line (e.g., nested blocks), it narrows down to the smallest, most specific statement container.
def _sink_stmt(fn, line: int) -> Optional[ast.stmt]:
    best = None
    for s in _stmts(fn):
        if s.lineno <= line <= (s.end_lineno or s.lineno):
            if best is None or (s.end_lineno - s.lineno) < (best.end_lineno - best.lineno):
                best = s
    return best

# Calculates a set of line numbers occupied by a statement. If header_only=True is passed for a block statement (like an if or while loop), it calculates only the line numbers of the conditional header rather than returning the entire loop body.
def _span(node: ast.stmt, header_only: bool = False) -> Set[int]:
    if header_only and isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
        first_body = node.body[0].lineno if node.body else node.lineno + 1
        return set(range(node.lineno, max(node.lineno + 1, first_body)))
    return set(range(node.lineno, (node.end_lineno or node.lineno) + 1))


def _value_names(stmt: ast.stmt) -> Set[str]:
    """Names the statement reads. For an assignment that is the right-hand side only."""
    if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
        return _names(stmt.value)
    if isinstance(stmt, ast.AugAssign):
        return _names(stmt.value)
    return _names(stmt)


def _target_names(stmt: ast.stmt) -> Set[str]:
    if isinstance(stmt, ast.Assign):
        return set().union(*[_names(t) for t in stmt.targets])
    if isinstance(stmt, (ast.AugAssign, ast.AnnAssign)):
        return _names(stmt.target)
    return set()


def _mutated_object(stmt: ast.stmt) -> Optional[str]:
    """For a statement like `conf.set("k", param)` or `items.append(x)`, return the object name ("conf")."""
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute):
        base = stmt.value.func.value
        if isinstance(base, ast.Name):
            return base.id
    return None


def _slice_lines(fn, sink: ast.stmt, trace_lines: Set[int]) -> Set[int]:
    """Backward slice inside one function: everything that can change the values the sink uses.

    Follows, until nothing new is found:
      - assignments to a relevant name (x = ..., x += ..., x: T = ...)
      - method calls that change a relevant object (conf.set(..., param), items.append(param))
      - for-loop and with-statement headers that bind a relevant name
      - if/while conditions that decide whether a kept line runs (control dependence), and the names they test
    Also keeps guards (if / while / assert) that test a relevant name, because a check that
    rejects bad input is often the reason an alert is a false positive.
    """
    wanted = {fn.lineno} | _span(sink) | trace_lines
    relevant = _value_names(sink)
    after = [s for s in _stmts(fn) if s.lineno > (sink.end_lineno or sink.lineno)]
    built = _target_names(sink)
    if built:   # the alert is on the line that builds a value (sql = f"..."): keep where that value is used
        later = sorted([s for s in after if isinstance(s, (ast.Expr, ast.Assign, ast.AugAssign, ast.Return))
                        and _names(s) & built], key=lambda s: s.lineno)
        for s in later[:3]:
            wanted |= _span(s)
            relevant |= _value_names(s) - built
    before = [s for s in _stmts(fn) if s.lineno < sink.lineno and not _span(sink) >= _span(s)]
    changed = True
    while changed:
        changed = False
        for s in before:
            if s.lineno in wanted and not isinstance(s, (ast.If, ast.While, ast.For, ast.With, ast.Try)):
                continue
            new: Set[str] = set()
            if isinstance(s, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and _target_names(s) & relevant:
                wanted |= _span(s)
                new = _value_names(s)
            elif _mutated_object(s) in relevant:
                wanted |= _span(s)
                new = _names(s)
            elif isinstance(s, ast.For) and _names(s.target) & relevant:
                wanted |= _span(s, header_only=True)
                new = _names(s.iter)
            elif isinstance(s, ast.With) and any(i.optional_vars is not None and _names(i.optional_vars) & relevant
                                                 for i in s.items):
                wanted |= _span(s, header_only=True)
                new = set().union(*[_names(i.context_expr) for i in s.items])
            if new - relevant:
                relevant |= new
                changed = True
        # Control dependence: if a kept line sits inside an if/while, keep the condition (and the else: line),
        # because the condition decides which assignment reaches the sink. Its names become relevant too.
        for s in before:
            if isinstance(s, (ast.If, ast.While)) and not _span(s, header_only=True) <= wanted:
                if (_span(s) - _span(s, header_only=True)) & wanted:
                    wanted |= _span(s, header_only=True)
                    if s.orelse:
                        wanted |= set(range(s.body[-1].end_lineno + 1, s.orelse[0].lineno))
                    if _names(s.test) - relevant:
                        relevant |= _names(s.test)
                    changed = True
            elif isinstance(s, ast.Match) and s.lineno not in wanted and (wanted - _span(sink)) & (_span(s) - {s.lineno}):
                wanted |= {s.lineno} | {c.pattern.lineno for c in s.cases}   # match line and every case line
                relevant |= _names(s.subject)
                changed = True
    for s in before:  # guard statements that mention relevant names
        if isinstance(s, (ast.If, ast.While)) and _names(s.test) & relevant:
            wanted |= _span(s) if (s.end_lineno - s.lineno) <= 6 else _span(s, header_only=True) | _span(s.body[0])
        elif isinstance(s, ast.Assert) and _names(s.test) & relevant:
            wanted |= _span(s)
    return wanted


def _helpers(tree: ast.AST, fn, wanted: Set[int]) -> Set[int]:
    by_name = {f.name: f for f in _functions(tree) if f is not fn}
    extra: Set[int] = set()
    for s in _stmts(fn):
        if _span(s) & wanted:
            for call in [n for n in ast.walk(s) if isinstance(n, ast.Call)]:
                name = call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", None)
                if name in by_name:
                    h = by_name[name]
                    extra |= set(range(h.lineno, (h.end_lineno or h.lineno) + 1))
    return extra


def _window(lines: List[str], line: int) -> Set[int]:
    return set(range(max(1, line - WINDOW), min(len(lines), line + WINDOW) + 1))


def build(finding: Finding, root: str, level: int = 2) -> Context:
    lines = _read(root, finding.file)
    note = ""
    try:
        tree = ast.parse("\n".join(lines))
    except SyntaxError:
        tree = None
    fn = enclosing_function(tree, finding.start_line) if tree else None
    if fn is None:
        wanted = _window(lines, finding.start_line)
        note = "No enclosing function found, used a window of nearby lines."
    elif level <= 1:
        wanted = set(range(fn.lineno, (fn.end_lineno or fn.lineno) + 1))
    else:
        sink = _sink_stmt(fn, finding.start_line)
        if sink is None:
            wanted = set(range(fn.lineno, (fn.end_lineno or fn.lineno) + 1))
            note = "Sink statement not found, used the whole function."
        else:
            trace_lines = {int(t.rsplit(":", 1)[1]) for t in finding.trace
                           if t.rsplit(":", 1)[0] == finding.file and t.rsplit(":", 1)[1].isdigit()
                           and fn.lineno <= int(t.rsplit(":", 1)[1]) <= (fn.end_lineno or fn.lineno)}
            if isinstance(sink, (ast.Import, ast.ImportFrom)):
                # The alert is on an import line ("use defusedxml"), which has no data flow of its own.
                # Slice from the later statements that use the imported module instead.
                mods = {(a.asname or a.name).split(".")[0] for a in sink.names}
                uses = [s for s in _stmts(fn) if s.lineno > sink.lineno and _names(s) & mods
                        and not isinstance(s, (ast.If, ast.While, ast.For, ast.With, ast.Try))][:3]
                wanted = _span(sink).union(*[_slice_lines(fn, u, trace_lines) for u in uses])
                note = "The alert is on an import line; the slice also shows where the module is used."
            else:
                wanted = _slice_lines(fn, sink, trace_lines)
            if level >= 3:
                wanted |= _helpers(tree, fn, wanted)
            if not finding.trace and not note:
                note = "No scanner trace, slice built from the code structure."
    chosen = sorted(n for n in wanted if 1 <= n <= len(lines))
    return Context(level=level, file=finding.file, lines=[(n, lines[n - 1]) for n in chosen], note=note)
