from dataclasses import field, dataclass
from enum import Enum
from typing import Dict, List
from zhixuewang.models import Exam, ExtendedList, Person, School, StuClass, Sex, Subject


class TeacherRole(Enum):
    TEACHER = "老师"
    HEADMASTER = "校长"
    GRADE_DIRECTER = "年级组长"

    def __str__(self):
        return self._value_


class TeaPerson(Person):
    def __init__(self,
                 name: str = "",
                 id: str = "",
                 gender: Sex = Sex.GIRL,
                 email: str = "",
                 mobile: str = "",
                 qq_number: str = "",
                 birthday: int = 0,
                 avatar: str = "",
                 code: str = "",
                 clazz: StuClass = None):
        super().__init__(name, id, gender, email, mobile, qq_number, birthday,
                         avatar)
        self.code = code
        self.clazz = clazz


# 单科 班级分类
@dataclass()
class RankData:
    schoolRankMap: Dict[str, Dict[float, int]]
    schoolsRankMap: Dict[str, Dict[str, Dict[float, int]]]
    # 总排名
    allRankMap: Dict[float, int]


@dataclass
class TopicTeacherMarkingProgress:
    teacher_name: str
    school: School
    is_online: bool
    teacher_code: str
    complete_count: int
    not_complete_count: int

    @property
    def complete_percent(self) -> float:
        if self.complete_count == 0 and self.not_complete_count == 0:
            return 100
        return (self.complete_count / (self.complete_count + self.not_complete_count)) * 100


@dataclass
class TopicMarkingProgress:
    disp_title: str
    topic_number: int
    complete_percent: float
    subject_id: str
    teachers: List[TopicTeacherMarkingProgress] = field(default_factory=list)


@dataclass
class SubjectMarkingProgress:
    subject: Subject
    markingProgresses: List[TopicMarkingProgress] = field(default_factory=list)


@dataclass
class ExamMarkingProgress:
    exam: Exam
    markingProgresses: List[SubjectMarkingProgress] = field(default_factory=list)
