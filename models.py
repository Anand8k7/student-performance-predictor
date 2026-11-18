import math

NAME_MAX_LENGTH = 50
NAME_EXTRA_CHARACTERS = " .'-_"


class Student:
    def __init__(self, name, study_hours, attendance,
                 internal1, internal2, assignment, semester_score=None):
        self.name = self._check_name(name)
        self.study_hours = self._check(study_hours, 0, 24, "Study hours")
        self.attendance = self._check(attendance, 0, 100, "Attendance")
        self.internal1 = self._check(internal1, 0, 30, "Internal 1")
        self.internal2 = self._check(internal2, 0, 30, "Internal 2")
        self.assignment = self._check(assignment, 0, 20, "Assignment")
        if semester_score is None:
            self.semester_score = None
        else:
            self.semester_score = self._check(semester_score, 0, 100, "Semester score")

    @staticmethod
    def _check_name(name):
        if not isinstance(name, str):
            raise ValueError("Name must be text")
        name = name.strip()
        if not name:
            raise ValueError("Name cannot be empty")
        if len(name) > NAME_MAX_LENGTH:
            raise ValueError(f"Name must be at most {NAME_MAX_LENGTH} characters")
        for character in name:
            if not (character.isalnum() or character in NAME_EXTRA_CHARACTERS):
                raise ValueError(
                    "Name can only contain letters, numbers, spaces and . ' - _"
                )
        return name

    @staticmethod
    def _check(value, low, high, label):
        if isinstance(value, bool):
            raise ValueError(f"{label} must be a number")
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{label} must be a number") from None
        if not math.isfinite(value):
            raise ValueError(f"{label} must be a real number")
        if not low <= value <= high:
            raise ValueError(f"{label} must be between {low} and {high}")
        return value

    def to_tuple(self):
        return (self.name, self.study_hours, self.attendance,
                self.internal1, self.internal2, self.assignment,
                self.semester_score)
