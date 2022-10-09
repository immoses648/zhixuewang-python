import base64
from enum import Enum
import pickle
import datetime
from dataclasses import dataclass, field
from zhixuewang.session import get_session
from zhixuewang.urls import Url


def get_property(arg_name: str) -> property:
    def setter(self, mill_timestamp):
        self.__dict__[arg_name] = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=(mill_timestamp / 1000))

    return property(fget=lambda self: self.__dict__[arg_name],
                    fset=setter)


class Role(Enum):
    student = 0,
    teacher = 1


@dataclass
class AccountData:
    username: str
    encoded_password: str
    role: Role


class Account:
    def __init__(self, session, role: Role) -> None:
        self._session = session
        self.role = role
        self.username = base64.b64decode(session.cookies["uname"].encode()).decode()

    def save_account(self, path: str = "user.data"):
        with open(path, "wb") as f:
            data = pickle.dumps(AccountData(self.username,
                                            base64.b64decode(self._session.cookies["pwd"].encode()).decode(),
                                            self.role))
            f.write(base64.b64encode(data))

    def update_login_status(self):
        """更新登录状态. 如果session过期自动重新获取"""
        r = self._session.get(Url.GET_LOGIN_STATE)
        data = r.json()
        if data["result"] == "success":
            return
        # session过期
        password = base64.b64decode(self._session.cookies["pwd"].encode()).decode()
        self._session = get_session(self.username, password)


@dataclass
class Phase:
    """学期, 比如七年级, 八年级"""
    name: str = ""
    code: str = ""


@dataclass
class Grade:
    """年级"""
    name: str = ""
    code: str = ""
    phase: Phase = field(default_factory=Phase)


@dataclass
class School:
    """学校"""
    id: str = ""
    name: str = ""

    def __str__(self):
        return self.name


class Sex(Enum):
    """性别"""
    GIRL = "女"
    BOY = "男"

    def __str__(self):
        return self._value_


@dataclass(eq=False)
class StuClass:
    """班级"""
    id: str = ""
    name: str = ""
    grade: Grade = field(default_factory=Grade, repr=False)
    school: School = field(default_factory=School, repr=False)

    def __eq__(self, other):
        return type(other) == type(self) and other.id == self.id

    def __str__(self):
        return f"学校: {self.school} 班级: {self.name}"

    def __repr__(self):
        return f"StuClass(id={self.id}, name={self.name}, school={self.school.__repr__()})"


@dataclass(repr=False)
class Person:
    """一些基本属性"""
    id: str = ""
    name: str = ""
    gender: Sex = Sex.GIRL
    email: str = ""
    mobile: str = ""
    qq_number: str = ""
    _birthday_timestamp: float = 0
    birthday = get_property("_birthday_timestamp")
    avatar: str = ""


@dataclass(repr=False)
class StuPerson(Person):
    """一些关于学生的信息"""
    code: str = ""
    clazz: StuClass = field(default_factory=StuClass, repr=False)

    def __str__(self):
        return f"{self.clazz} 姓名: {self.name} 性别: {self.gender} " \
               f"{f'QQ: {self.qq_number} ' if self.qq_number != '' else ''}" \
               f"{f'手机号码: {self.mobile}' if self.mobile != '' else ''}"

    def __repr__(self):
        return f"Person(id={self.id}, clazz={self.clazz.__repr__()}, name={self.name}, gender={self.gender}" \
               f"{f', qq_number={self.qq_number}' if self.qq_number != '' else ''}" \
               f"{f', mobile={self.mobile}' if self.mobile != '' else ''}" + ")"

class TeacherRole(Enum):
    TEACHER = "老师"
    HEADMASTER = "校长"
    GRADE_DIRECTER = "年级组长"

    def __str__(self):
        return self._value_


class TeaPerson(Person):
    def __init__(self,
                 name: str = "",
                 person_id: str = "",
                 gender: Sex = Sex.GIRL,
                 email: str = "",
                 mobile: str = "",
                 qq_number: str = "",
                 birthday: int = 0,
                 avatar: str = "",
                 code: str = "",
                 clazz: StuClass = None):
        super().__init__(name, person_id, gender, email, mobile, qq_number, birthday,
                         avatar)
        self.code = code
        self.clazz = clazz