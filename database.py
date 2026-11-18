import sqlite3
import pandas as pd
from logger_config import get_logger
from models import Student

logger = get_logger("database")

REQUIRED_COLUMNS = ["name", "study_hours", "attendance",
                    "internal1", "internal2", "assignment", "semester_score"]
MAX_CSV_ROWS = 10000
MAX_ERRORS_SHOWN = 5

INSERT_SQL = (
    "INSERT INTO students (name, study_hours, attendance, "
    "internal1, internal2, assignment, semester_score) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)"
)


class Database:
    def __init__(self, db_name="students.db"):
        self.db_name = db_name
        self._create_table()

    def _connect(self):
        return sqlite3.connect(self.db_name)

    def _create_table(self):
        conn = self._connect()
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS students (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        study_hours REAL,
                        attendance REAL,
                        internal1 REAL,
                        internal2 REAL,
                        assignment REAL,
                        semester_score REAL
                    )
                """)
        finally:
            conn.close()

        def add_student(self, student):
        conn = self._connect()
        try:
            with conn:
                conn.execute(INSERT_SQL, student.to_tuple())
            logger.info("Added one student record")
        except sqlite3.Error as e:
            logger.error(f"Database error while adding student: {e}")
            raise
        finally:
            conn.close()

    @staticmethod
    def _validate_csv(df):
        missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
        if missing:
            raise ValueError(
                "CSV file is missing required columns: " + ", ".join(missing)
            )
        if len(df) > MAX_CSV_ROWS:
            raise ValueError(
                f"CSV file has too many rows (maximum {MAX_CSV_ROWS})"
            )

        students = []
        errors = []
        rows = df[REQUIRED_COLUMNS].itertuples(index=False)
        for position, row in enumerate(rows, start=2):
            try:
                students.append(Student(*row))
            except ValueError as error:
                errors.append(f"Row {position}: {error}")

        if errors:
            shown = "; ".join(errors[:MAX_ERRORS_SHOWN])
            extra = len(errors) - MAX_ERRORS_SHOWN
            if extra > 0:
                shown += f"; and {extra} more problems"
            raise ValueError(f"CSV file rejected, nothing was saved. {shown}")
        return students

    def load_csv(self, path):
        try:
            df = pd.read_csv(path, dtype=str)
        except (pd.errors.EmptyDataError, pd.errors.ParserError):
            raise ValueError("CSV file could not be read") from None

        students = self._validate_csv(df)

        conn = self._connect()
        try:
            with conn:
                conn.executemany(INSERT_SQL, [s.to_tuple() for s in students])
        except sqlite3.Error as e:
            logger.error(f"Database error while loading CSV: {e}")
            raise
        finally:
            conn.close()
        logger.info(f"Loaded {len(students)} validated rows from CSV")

    def get_all(self):
        conn = self._connect()
        try:
            return pd.read_sql("SELECT * FROM students", conn)
        finally:
            conn.close()
