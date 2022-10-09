import hashlib
import time
import uuid
from json import JSONDecodeError
import asyncio
import json
from typing import List
import httpx
import rsa
import requests
import base64
from enum import Enum
import pickle
import datetime
from dataclasses import dataclass, field


# EXCEPTIONS
class Error(Exception):
    value: str

    def __str__(self):
        return str(self.value)


class LoginError(Error):
    def __init__(self, value):
        self.value = value


class UserOrPassError(LoginError):
    def __init__(self, value=None):
        super().__init__(value or "用户名或密码错误!")


class UserNotFoundError(LoginError):
    def __init__(self, value=None):
        super().__init__(value or "用户不存在!")


class UserDefunctError(LoginError):
    def __init__(self, value=None):
        super().__init__(value or "用户已失效!")


class RoleError(Error):
    def __init__(self, value=None):
        self.value = value or "账号是未知用户"


class ArgError(Error):
    def __init__(self, value=None):
        self.value = value or "请输入正确的参数!"


class PageConnectionError(Error):
    def __init__(self, value):
        self.value = value


class PageInformationError(Error):
    def __init__(self, value):
        self.value = value


# URLS
BASE_DOMAIN = "zhixue.com"
BASE_URL = f"https://www.{BASE_DOMAIN}"


class URLs:
    SERVICE_URL = f"{BASE_URL}:443/ssoservice.jsp"
    SSO_URL = f"https://sso.{BASE_DOMAIN}/sso_alpha/login?service={SERVICE_URL}"
    TEST_PASSWORD_URL = f"{BASE_URL}/weakPwdLogin/?from=web_login"
    TEST_URL = f"{BASE_URL}/container/container/teacher/teacherAccountNew"
    GET_LOGIN_STATE = f"{BASE_URL}/loginState/"

    # STUDENT

    INFO_URL = f"{BASE_URL}/container/container/student/account/"

    # Exam
    XTOKEN_URL = f"{BASE_URL}/addon/error/book/index"
    GET_STU_EXAM_URL = f"{BASE_URL}/zhixuebao/report/exam/getUserExamList"
    GET_RECENT_EXAM_URL = f"{BASE_URL}/zhixuebao/report/exam/getRecentExam"
    GET_MARK_URL = f"{BASE_URL}/zhixuebao/report/exam/getReportMain"
    GET_ORIGINAL_URL = f"{BASE_URL}/zhixuebao/report/checksheet/"

    # Person
    GET_CLAZZS_URL = f"{BASE_URL}/zhixuebao/zhixuebao/friendmanage/"
    # GET_CLASSMATES_URL = f"{BASE_URL}/zhixuebao/zhixuebao/getClassStudent/"
    GET_CLASSMATES_URL = f"{BASE_URL}/container/contact/student/students"
    GET_TEACHERS_URL = f"{BASE_URL}/container/contact/student/teachers"

    GET_EXAM_LEVEL_TREND_URL = f"{BASE_URL}/zhixuebao/report/exam/getLevelTrend"
    GET_PAPER_LEVEL_TREND_URL = f"{BASE_URL}/zhixuebao/report/paper/getLevelTrend"
    GET_LOST_TOPIC_URL = f"{BASE_URL}/zhixuebao/report/paper/getExamPointsAndScoringAbility"
    GET_SUBJECT_DIAGNOSIS = f"{BASE_URL}/zhixuebao/report/exam/getSubjectDiagnosis"

    # TEACHER

    GET_TEA_EXAM_URL = f"{BASE_URL}/classreport/class/classReportList/"
    GET_AcademicTermTeachingCycle_URL = f"{BASE_URL}/classreport/class/getAcademicTermTeachingCycle/"

    GET_MARKING_PROGRESS_URL = f"{BASE_URL}/marking/marking/markingProgressDetail"

    GET_EXAM_DETAIL_URL = f"{BASE_URL}/scanmuster/cloudRec/scanrecognition"

    GET_EXAM_SCHOOLS_URL = f"{BASE_URL}/exam/marking/schoolClass"
    GET_EXAM_SUBJECTS_URL = f"{BASE_URL}/configure/class/getSubjectsIncludeSubAndGroup"
    ORIGINAL_PAPER_URL = f"{BASE_URL}/classreport/class/student/checksheet/"


# MODELS
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
        r = self._session.get(URLs.GET_LOGIN_STATE)
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


# MAIN CLASSES
class StudentAccount(Account, StuPerson):
    """学生账号"""

    def __init__(self, session):
        super().__init__(session, Role.student)
        self._token = None
        self._timestamp = None

    def _get_auth_header(self) -> dict:
        """获取header"""
        self.update_login_status()
        auth_guid = str(uuid.uuid4())
        auth_time_stamp = str(int(time.time() * 1000))
        md5 = hashlib.md5()
        md5.update((auth_guid + auth_time_stamp + "iflytek!@#123student").encode(encoding="utf-8"))
        auth_token = md5.hexdigest()
        token = self._token
        cur_time = self._timestamp
        if token and time.time() - cur_time < 600:  # 判断token是否过期
            return {
                "authbizcode": "0001",
                "authguid": auth_guid,
                "authtimestamp": auth_time_stamp,
                "authtoken": auth_token,
                "XToken": token
            }
        r = self._session.get(URLs.XTOKEN_URL, headers={
            "authbizcode": "0001",
            "authguid": auth_guid,
            "authtimestamp": auth_time_stamp,
            "authtoken": auth_token
        })
        if not r.ok:
            raise PageConnectionError(
                f"_get_auth_header中出错, 状态码为{r.status_code}")
        try:
            if r.json()["errorCode"] != 0:
                raise PageInformationError(
                    f"_get_auth_header出错, 错误信息为{r.json()['errorInfo']}")
            self._token = r.json()["result"]
        except (JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"_get_auth_header中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")
        self._timestamp = time.time()
        return self._get_auth_header()

    def set_base_info(self):
        """设置账户基本信息, 如用户id, 姓名, 学校等"""
        self.update_login_status()
        r = self._session.get(URLs.INFO_URL)
        if not r.ok:
            raise PageConnectionError(f"set_base_info出错, 状态码为{r.status_code}")
        try:
            json_data = r.json()["student"]
            if not json_data.get("clazz", False):
                raise UserDefunctError()
            self.code = json_data.get("code")
            self.name = json_data.get("name")
            self.avatar = json_data.get("avatar")
            self.gender = Sex.BOY if json_data.get(
                "gender") == "1" else Sex.GIRL
            self.username = json_data.get("loginName")
            self.id = json_data.get("id")
            self.mobile = json_data.get("mobile")
            self.email = json_data.get("email")
            self.qq_number = json_data.get("im")
            self.clazz = StuClass(
                id=json_data["clazz"]["id"],
                name=json_data["clazz"]["name"],
                school=School(
                    id=json_data["clazz"]["division"]["school"]["id"],
                    name=json_data["clazz"]["division"]["school"]["name"]),
                grade=Grade(code=json_data["clazz"]["division"]["grade"]["code"],
                            name=json_data["clazz"]["division"]["grade"]["name"],
                            phase=Phase(code=json_data["clazz"]["division"]
                            ["grade"]["phase"]["code"],
                                        name=json_data["clazz"]["division"]
                                        ["grade"]["phase"]["name"])))
            self.birthday = json_data.get("birthday", 0)
        except (JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"set_base_info中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")
        return self

    def get_student_account_info(self) -> dict:
        """获取学生账号信息"""
        self.update_login_status()
        r = self._session.get(URLs.INFO_URL)
        if not r.ok:
            raise PageConnectionError(
                f"get_student_account_info出错, 状态码为{r.status_code}")
        try:
            json_data = r.json()
            if not json_data.get("student", False):
                raise UserDefunctError()
            return json_data
        except (JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"get_student_account_info中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")

    def get_user_exam_list(self, page_index: int = 1, page_size: int = 10) -> dict:
        """获取指定页数的考试列表"""
        self.update_login_status()
        r = self._session.get(URLs.GET_STU_EXAM_URL,
                              params={
                                  "pageIndex": page_index,
                                  "pageSize": page_size
                              },
                              headers=self._get_auth_header())
        if not r.ok:
            raise PageConnectionError(
                f"get_page_exam中出错, 状态码为{r.status_code}")
        try:
            return r.json()
        except (JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"get_page_exam中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")

    def get_recent_exam(self) -> dict:  # 已重写
        """获取最新考试"""
        self.update_login_status()
        r = self._session.get(URLs.GET_RECENT_EXAM_URL,
                              headers=self._get_auth_header())
        if r.ok:
            return r.json()
        raise PageConnectionError(
            f"get_latest_exam中出错, 状态码为{r.status_code}")

    def get_exams(self) -> list:  # 已重写，非官方
        """获取所有考试"""
        i = 1
        check = True
        exams = []
        while check:
            cur_exams = self.get_user_exam_list(i, 100)
            exams.extend(cur_exams['result']['examList'])
            check = cur_exams['result']['hasNextPage']
            i += 1
        return exams

    def get_report_main(self, exam: str = None) -> dict:  # 已重写
        self.update_login_status()
        if not exam:
            exam = self.get_recent_exam()["result"]["examInfo"]["examId"]
        r = self._session.get(URLs.GET_MARK_URL,
                              params={"examId": exam},
                              headers=self._get_auth_header())
        if not r.ok:
            raise PageConnectionError(
                f"出错, 状态码为{r.status_code}")
        try:
            return r.json()
        except (JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"__get_self_mark中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")

    def get_checksheet(self, subject_id: str, exam_id=None):
        if exam_id is None:
            exam_id = self.get_recent_exam()["result"]["examInfo"]["examId"]
        self.update_login_status()
        r = self._session.get(URLs.GET_ORIGINAL_URL,
                              params={
                                  "examId": exam_id,
                                  "paperId": subject_id,
                              },
                              headers=self._get_auth_header())
        if not r.ok:
            raise PageConnectionError(
                f"__get_original中出错, 状态码为{r.status_code}")
        try:
            return r.json()
        except (JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"__get_original中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")

    def get_zhixuebao_friendmanage(self):  # 已重写
        """获取当前年级所有班级"""
        r = self._session.get(URLs.GET_CLAZZS_URL,
                              params={"d": int(time.time())})
        if not r.ok:
            raise PageConnectionError(f"get_clazzs中出错, 状态码为{r.status_code}")
        try:
            return r.json()
        except (JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"get_clazzs中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")

    def get_contact_students(self, clazz_id: str = None) -> list:  # 已重写
        """获取班级所有学生"""
        if clazz_id is None:
            clazz_id = self.clazz.id
        self.update_login_status()
        r = self._session.get(URLs.GET_CLASSMATES_URL,
                              params={
                                  "r": f"{self.id}student",
                                  "clazzId": clazz_id
                              })
        if not r.ok:
            raise PageConnectionError(
                f"__get_classmates中出错, 状态码为{r.status_code}")
        try:
            return r.json()
        except (JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"__get_classmates中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")

    def get_contact_teachers(self) -> list:  # 已重写
        """获取班级所有老师"""
        self.update_login_status()
        r = self._session.get(URLs.GET_TEACHERS_URL)
        if not r.ok:
            raise PageConnectionError(
                f"__get_classmates中出错, 状态码为{r.status_code}")
        try:
            return r.json()
        except (JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"内容发生改变, 错误为{e}, 内容为\n{r.text}")

    def get_exam_level_trend(self, exam_id: str = None, page_index: int = 1, page_size: int = 100) -> dict:  # 已重写
        """获取等级趋势"""
        if exam_id is None:
            exam_id = self.get_recent_exam()["result"]["examInfo"]["examId"]
        self.update_login_status()
        r = self._session.get(URLs.GET_EXAM_LEVEL_TREND_URL, params={
            "examId": exam_id,
            "pageIndex": page_index,
            "pageSize": page_size
        }, headers=self._get_auth_header())
        if r.ok:
            return r.json()

    def get_subject_diagnosis(self, exam_id: str = None) -> dict:  # 已重写
        """获取学科诊断"""
        if exam_id is None:
            exam_id = self.get_recent_exam()["result"]["examInfo"]["examId"]
        self.update_login_status()
        r = self._session.get(URLs.GET_SUBJECT_DIAGNOSIS, params={
            "examId": exam_id
        }, headers=self._get_auth_header())
        if r.ok:
            return r.json()


class TeacherAccount(Account, TeaPerson):
    """老师账号"""

    def __init__(self, session):
        super().__init__(session, Role.teacher)
        self._token = None

    def set_base_info(self):
        r = self._session.get(
            URLs.TEST_URL,
            headers={
                "referer":
                    "https://www.zhixue.com/container/container/teacher/index/"
            })
        json_data = r.json()["teacher"]
        self.email = json_data.get("email")
        self.gender = Sex.BOY if json_data["gender"] == "1" else Sex.GIRL
        self.id = json_data.get("id")
        self.mobile = json_data.get("mobile")
        self.name = json_data.get("name")
        return self

    async def __get_marking_school_class(self, school_id: str, subject_id: str) -> List[StuClass]:
        async with httpx.AsyncClient(cookies=self._session.cookies) as client:
            r = await client.get(URLs.GET_EXAM_SCHOOLS_URL, params={
                "schoolId": school_id,
                "markingPaperId": subject_id
            })
            return r.json()

    def get_marking_school_class(self, school_id: str, subject_id: str):
        self.update_login_status()
        return asyncio.run(self.__get_marking_school_class(school_id, subject_id))

    def get_original_paper(self, user_id: str, paper_id: str, save_to_path: str):
        """
        获得原卷
        Args:
            user_id (str): 为需要查询原卷的userId
            paper_id (str): 为需要查询的学科ID(topicSetId)
            save_to_path (str): 为原卷保存位置(html文件), 精确到文件名
        """
        data = self._session.get(URLs.ORIGINAL_PAPER_URL, params={
            "userId": user_id,
            "paperId": paper_id
        })
        with open(save_to_path, encoding="utf-8", mode="w+") as fhandle:
            # 替换html内容，让文件可以正常显示
            fhandle.writelines(data.text.replace(
                "//static.zhixue.com", "https://static.zhixue.com"))

    def get_subjects_include_sub_and_group(self, exam_id: str):
        self.update_login_status()
        r = self._session.get(URLs.GET_EXAM_SUBJECTS_URL, params={
            "examId": exam_id
        })
        return r.json()

    def get_scanrecognition(self, exam_id: str):
        """获取考试详情"""
        self.update_login_status()
        r = self._session.post(URLs.GET_EXAM_DETAIL_URL, data={
            "examId": exam_id
        })
        return r.json()

    def get_marking_progress_detail(self, subject_id: str, school_id: str = ""):
        return self._session.post(URLs.GET_MARKING_PROGRESS_URL, data={
            "progressParam": json.dumps({
                "markingPaperId": subject_id,
                "topicNum": None,
                "subTopicIndex": None,
                "topicStartNum": None,
                "schoolId": school_id,
                "topicProgress": "",
                "teacherProgress": "",
                "isOnline": "",
                "teacherName": "",
                "userId": "",
                "examId": ""
            })
        }).json()

    async def _get_marking_progress_detail_async(self, subject_id: str, school_id: str):
        async with httpx.AsyncClient(cookies=self._session.cookies) as client:
            r = await client.post(URLs.GET_MARKING_PROGRESS_URL, data={
                "progressParam": json.dumps({
                    "markingPaperId": subject_id,
                    "topicNum": None,
                    "subTopicIndex": None,
                    "topicStartNum": None,
                    "schoolId": school_id,
                    "topicProgress": "",
                    "teacherProgress": "",
                    "isOnline": "",
                    "teacherName": "",
                    "userId": "",
                    "examId": ""
                })
            })
            return r.json()

    def get_token(self) -> str:
        if self._token is not None:
            return self._token
        r = self._session.get(
            "https://www.zhixue.com/container/app/token/getToken")
        self._token = r.json()["result"]
        return self._token

    def get_headers(self):
        return {"token": self.get_token()}


# SESSION
def get_session(username: str, password: str, _type: str = "auto") -> requests.Session:
    """通过用户名和密码获取session

    默认可支持zx, zxt和tch开头的账号, 准考证号以及手机号
    可通过改变type为id来支持使用用户id

    Args:
        username (str): 用户名, 可以为准考证号, 手机号, id
        password (str): 密码(包括加密后的密码)
        _type (str): 登录方式, 为id时表示用id登录, 为auto时表示自动选择登录方式

    Raises:
        UserOrPassError: 用户名或密码错误
        UserNotFoundError: 未找到用户
        LoginError: 登录错误

    Returns:
        requests.session:
    """
    if len(password) != 32:
        e = "010001"
        m = "008c147f73c2593cba0bd007e60a89ade5"
        keylength = rsa.common.byte_size(rsa.PublicKey(int(m, 16), int(e, 16)).n)
        padding = b''
        for i in range(keylength - len(password.encode()[::-1]) - 3):
            padding += b'\x00'
        padded = b''.join([b'\x00\x00', padding, b'\x00', password.encode()[::-1]])

        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload,
                                         rsa.PublicKey(int(m, 16), int(e, 16)).e,
                                         rsa.PublicKey(int(m, 16), int(e, 16)).n)
        block = rsa.transform.int2bytes(encrypted, keylength)

        password = block.hex()
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1"
    r = session.get(URLs.SSO_URL)
    json_obj = json.loads(r.text.strip().replace("\\", "").replace("'", "")[1:-1])
    if json_obj["code"] != 1000:
        raise LoginError(json_obj["data"])
    lt = json_obj["data"]["lt"]
    execution = json_obj["data"]["execution"]
    r = session.get(URLs.SSO_URL,
                    params={
                        "encode": "true",
                        "sourceappname": "tkyh,tkyh",
                        "_eventId": "submit",
                        "appid": "zx-container-client",
                        "client": "web",
                        "type": "loginByNormal",
                        "key": _type,
                        "lt": lt,
                        "execution": execution,
                        "customLogoutUrl": "https://www.zhixue.com/login.html",
                        "username": username,
                        "password": password
                    })
    json_obj = json.loads(r.text.strip().replace("\\", "").replace("'", "")[1:-1])
    if json_obj["code"] != 1001:
        if json_obj["code"] == 1002:
            raise UserOrPassError()
        if json_obj["code"] == 2009:
            raise UserNotFoundError()
        raise LoginError(json_obj["data"])
    ticket = json_obj["data"]["st"]
    session.post(URLs.SERVICE_URL, data={
        "action": "login",
        "ticket": ticket,
    })
    session.cookies.set("uname", base64.b64encode(username.encode()).decode())
    session.cookies.set("pwd", base64.b64encode(password.encode()).decode())
    return session


def load_account(path: str = "user.data") -> Account:
    with open(path, "rb") as f:
        data = base64.b64decode(f.read())
        account_data: AccountData = pickle.loads(data)
        session = get_session(account_data.username, account_data.encoded_password)
        if account_data.role == Role.student:
            return StudentAccount(session).set_base_info()
        elif account_data.role == Role.teacher:
            return TeacherAccount(session).set_base_info()
        else:
            raise RoleError()


def login_student_id(user_id: str, password: str) -> StudentAccount:
    """通过用户id和密码登录学生账号

    Args:
        user_id (str): 用户id
        password (str): 密码(包括加密后的密码)

    Raises:
        UserOrPassError: 用户名或密码错误
        UserNotFoundError: 未找到用户
        LoginError: 登录错误

    Returns:
        StudentAccount
    """
    session = get_session(user_id, password, "id")
    student = StudentAccount(session)
    return student.set_base_info()


def login_student(username: str, password: str) -> StudentAccount:
    """通过用户名和密码登录学生账号

    Args:
        username (str): 用户名, 可以为准考证号, 手机号
        password (str): 密码(包括加密后的密码)

    Raises:
        UserOrPassError: 用户名或密码错误
        UserNotFoundError: 未找到用户
        LoginError: 登录错误

    Returns:
        StudentAccount
    """
    session = get_session(username, password)
    student = StudentAccount(session)
    return student.set_base_info()


def login_teacher_id(user_id: str, password: str) -> TeacherAccount:
    """通过用户id和密码登录老师账号

    Args:
        user_id (str): 用户id
        password (str): 密码(包括加密后的密码)

    Raises:
        UserOrPassError: 用户名或密码错误
        UserNotFoundError: 未找到用户
        LoginError: 登录错误

    Returns:
        TeacherAccount
    """
    session = get_session(user_id, password, "id")
    teacher = TeacherAccount(session)
    return teacher.set_base_info()


def login_teacher(username: str, password: str) -> TeacherAccount:
    """通过用户名和密码登录老师账号

    Args:
        username (str): 用户名, 可以为准考证号, 手机号
        password (str): 密码(包括加密后的密码)

    Raises:
        UserOrPassError: 用户名或密码错误
        UserNotFoundError: 未找到用户
        LoginError: 登录错误

    Returns:
        TeacherAccount
    """
    session = get_session(username, password)
    teacher = TeacherAccount(session)
    return teacher.set_base_info()


def login_id(user_id: str, password: str) -> Account:
    """通过用户id和密码登录智学网

    Args:
        user_id (str): 用户id
        password (str): 密码(包括加密后的密码)

    Raises:
        UserOrPassError: 用户名或密码错误
        UserNotFoundError: 未找到用户
        LoginError: 登录错误
        RoleError: 账号角色未知

    Returns:
        Person
    """
    session = get_session(user_id, password, "id")
    if "student" in session.get("https://www.zhixue.com/container/container/index/").url:
        return StudentAccount(session).set_base_info()
    return TeacherAccount(session).set_base_info()


def login(username: str, password: str) -> Account:
    """通过用户名和密码登录智学网

    Args:
        username (str): 用户名, 可以为准考证号, 手机号
        password (str): 密码(包括加密后的密码)

    Raises:
        ArgError: 参数错误
        UserOrPassError: 用户名或密码错误
        UserNotFoundError: 未找到用户
        LoginError: 登录错误
        RoleError: 账号角色未知

    Returns:
        Person
    """
    session = get_session(username, password)
    if "student" in session.get("https://www.zhixue.com/container/container/index/").url:
        return StudentAccount(session).set_base_info()
    return TeacherAccount(session).set_base_info()


def rewrite_str(model):
    """重写类的__str__方法

    Args:
        model: 需重写__str__方法的类

    Examples:
        >>> @rewrite_str(School)
        >>> def _(self: School):
        >>>     return f"<id: {self.id}, name: {self.name}>"
        >>> print(School("test id", "test school"))
        <id: test id, name: test school>
    """

    def str_decorator(func):
        model.__str__ = func
        return func

    return str_decorator
