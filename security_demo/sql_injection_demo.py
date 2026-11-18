"""
SQL injection demonstration (DEMO ONLY).

This file is NOT part of the app and is never imported by it.
It uses a temporary in-memory database with fake sample data.
The "unsafe" function exists only to show what NOT to do.
"""
import os
import sqlite3
import sys

# Allow "from models import Student" when run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models import Student

SAMPLE_STUDENTS = [
    ("Asha", 78.0),
    ("Ravi", 65.5),
    ("Meera", 91.0),
]

ATTACK_TEXT = "' OR '1'='1"
BOBBY_TABLES = "Robert'); DROP TABLE students;--"


def make_demo_database():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE students (name TEXT, semester_score REAL)")
    conn.executemany("INSERT INTO students VALUES (?, ?)", SAMPLE_STUDENTS)
    conn.commit()
    return conn


def unsafe_search(conn, typed_name):
    # UNSAFE: the typed text is glued into the SQL sentence.
    sql = ("SELECT name, semester_score FROM students WHERE name = '"
           + typed_name + "'")
    return sql, conn.execute(sql).fetchall()


def safe_search(conn, typed_name):
    # SAFE: the ? placeholder means the typed text is only ever data.
    sql = "SELECT name, semester_score FROM students WHERE name = ?"
    return sql, conn.execute(sql, (typed_name,)).fetchall()


def show(title):
    print()
    print("=== " + title + " ===")


def main():
    checks = []
    conn = make_demo_database()

    show("Part 1: a normal search for Asha")
    sql, rows = unsafe_search(conn, "Asha")
    print("UNSAFE SQL :", sql)
    print("  rows returned:", len(rows))
    checks.append(("unsafe query works for normal input", len(rows) == 1))
    sql, rows = safe_search(conn, "Asha")
    print("SAFE SQL   :", sql)
    print("  rows returned:", len(rows))
    checks.append(("safe query works for normal input", len(rows) == 1))

    show("Part 2: the attack text  ' OR '1'='1")
    sql, rows = unsafe_search(conn, ATTACK_TEXT)
    print("UNSAFE SQL :", sql)
    print("  rows returned:", len(rows), "(ALL students leaked!)")
    checks.append(("unsafe query leaks every row", len(rows) == 3))
    sql, rows = safe_search(conn, ATTACK_TEXT)
    print("SAFE SQL   :", sql)
    print("  rows returned:", len(rows), "(attack text treated as a plain name)")
    checks.append(("safe query returns nothing for attack text", len(rows) == 0))

    show("Part 3: storing the classic 'Bobby Tables' text safely")
    conn.execute("INSERT INTO students VALUES (?, ?)", (BOBBY_TABLES, 50.0))
    conn.commit()
    tables = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")]
    stored = conn.execute(
        "SELECT name FROM students WHERE name = ?", (BOBBY_TABLES,)).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM students").fetchone()[0]
    print("Tables still present:", tables)
    print("Stored exactly as plain text:", stored[0][0])
    print("Total rows now:", total)
    checks.append(("students table still exists", "students" in tables))
    checks.append(("name stored exactly as plain text",
                   len(stored) == 1 and stored[0][0] == BOBBY_TABLES))
    checks.append(("no rows were lost", total == 4))

    show("Part 4: the app's own validation also blocks that text")
    expected = "Name can only contain letters, numbers, spaces and . ' - _"
    try:
        Student(BOBBY_TABLES, 5, 80, 15, 15, 10)
        message = "was accepted"
    except ValueError as error:
        message = str(error)
    print("Student() refused it:", message)
    checks.append(("Student validation rejects the attack name",
                   message == expected))

    conn.close()

    show("Results")
    for label, ok in checks:
        print("PASS" if ok else "FAIL", "-", label)
    passed = sum(ok for _, ok in checks)
    print()
    print(passed, "of", len(checks), "checks passed")


if __name__ == "__main__":
    main()
