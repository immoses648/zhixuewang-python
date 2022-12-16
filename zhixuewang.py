import re
import time
import uuid
import json
import rsa
import httpx
import base64
import pickle
import asyncio
import hashlib
import datetime
import requests
from dataclasses import dataclass


# EXCEPTIONS
class Error(Exception):
    value: str

    def __str__(self):
        return str(self.value)


class LoginError(Error):
    def __init__(self, value):
        self.value = value


class UsernameOrPasswordError(LoginError):
    def __init__(self, value=None):
        super().__init__(value or "用户名或密码错误!")


class UserNotFoundError(LoginError):
    def __init__(self, value=None):
        super().__init__(value or "用户不存在!")


class UserDefunctError(LoginError):
    def __init__(self, value=None):
        super().__init__(value or "用户已失效!")


class PageConnectionError(Error):
    def __init__(self, value):
        self.value = value


class PageInformationError(Error):
    def __init__(self, value):
        self.value = value


# URLS
class URLs:
    BASE_DOMAIN = "zhixue.com"
    BASE_URL = f"https://www.{BASE_DOMAIN}"
    SERVICE_URL = f"{BASE_URL}:443/ssoservice.jsp"
    SSO_URL = f"https://sso.{BASE_DOMAIN}/sso_alpha/login?service={SERVICE_URL}"
    TEST_URL = f"{BASE_URL}/container/container/teacher/teacherAccountNew"
    GET_LOGIN_STATE = f"{BASE_URL}/loginState/"

    # STUDENT
    INFO_URL = f"{BASE_URL}/container/container/student/account/"
    XTOKEN_URL = f"{BASE_URL}/addon/error/book/index"
    GET_CLAZZS_URL = f"{BASE_URL}/zhixuebao/zhixuebao/friendmanage/"
    GET_CLASSMATES_URL = f"{BASE_URL}/container/contact/student/students"
    GET_TEACHERS_URL = f"{BASE_URL}/container/contact/student/teachers"
    GET_STU_EXAM_URL = f"{BASE_URL}/zhixuebao/report/exam/getUserExamList"
    GET_RECENT_EXAM_URL = f"{BASE_URL}/zhixuebao/report/exam/getRecentExam"
    GET_MARK_URL = f"{BASE_URL}/zhixuebao/report/exam/getReportMain"
    GET_ORIGINAL_URL = f"{BASE_URL}/zhixuebao/report/checksheet/"
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
    GET_SIMPLE_ANSWER_RECORDS_URL = f"{BASE_URL}/commonment/class/getSimpleAnswerRecords/"


# MODELS
def get_property(arg_name: str) -> property:
    def setter(self, mill_timestamp):
        self.__dict__[arg_name] = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=(mill_timestamp / 1000))

    return property(fget=lambda self: self.__dict__[arg_name],
                    fset=setter)


@dataclass
class AccountData:
    username: str
    encoded_password: str


class Account:
    def __init__(self, session) -> None:
        self._session = session
        self._token = None
        self.role = None
        self.username = base64.b64decode(session.cookies["uname"].encode()).decode()
        self.info = None

    def save_account(self, path: str = "user.data"):
        with open(path, "wb") as f:
            data = pickle.dumps(AccountData(self.username,
                                            base64.b64decode(self._session.cookies["pwd"].encode()).decode()))
            f.write(base64.b64encode(data))

    def update_login_status(self):
        """更新登录状态. 如果session过期自动重新获取"""
        if self._session.get(URLs.GET_LOGIN_STATE).json()["result"] == "success":
            pass
        # session过期
        else:
            self._session = login(username=self.username,
                                  password=base64.b64decode(
                                      self._session.cookies["pwd"].encode()).decode(), _data=False)
        return


# MAIN CLASSES
class StudentAccount(Account):
    """学生账号"""

    def __init__(self, session):
        super().__init__(session)
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
        except (json.JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"_get_auth_header中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")
        self._timestamp = time.time()
        return self._get_auth_header()

    def set_base_info(self):
        """设置账户基本信息, 如用户id等"""
        self.update_login_status()
        r = self._session.get(URLs.INFO_URL)
        if not r.ok:
            raise PageConnectionError(f"set_base_info出错, 状态码为{r.status_code}")
        try:
            json_data = r.json()["student"]
            if not json_data.get("clazz", False):
                raise UserDefunctError()
            self.info = json_data
        except (json.JSONDecodeError, KeyError) as e:
            raise PageInformationError(f"set_base_info中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")
        return self

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
            raise PageConnectionError(f"get_page_exam中出错, 状态码为{r.status_code}")
        try:
            return r.json()
        except (json.JSONDecodeError, KeyError) as e:
            raise PageInformationError(f"get_page_exam中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")

    def get_recent_exam(self) -> dict:  # 已重写
        """获取最新考试"""
        self.update_login_status()
        r = self._session.get(URLs.GET_RECENT_EXAM_URL, headers=self._get_auth_header())
        if r.ok:
            return r.json()
        raise PageConnectionError(f"get_latest_exam中出错, 状态码为{r.status_code}")

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
            raise PageConnectionError(f"出错, 状态码为{r.status_code}")
        return r.json()

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
        return r.json()

    def get_zhixuebao_friendmanage(self):  # 已重写
        """获取当前年级所有班级"""
        r = self._session.get(URLs.GET_CLAZZS_URL,
                              params={"d": int(time.time())})
        if not r.ok:
            raise PageConnectionError(f"get_clazzs中出错, 状态码为{r.status_code}")
        return r.json()

    def get_contact_students(self, clazz_id: str = None) -> list:  # 已重写
        """获取班级所有学生"""
        self.update_login_status()
        if clazz_id is None:
            clazz_id = self.info['clazz']['id']
        r = self._session.get(URLs.GET_CLASSMATES_URL, params={"r": f"{self.info['id']}student", "clazzId": clazz_id})
        if not r.ok:
            raise PageConnectionError(
                f"__get_classmates中出错, 状态码为{r.status_code}")
        try:
            return r.json()
        except (json.JSONDecodeError, KeyError) as e:
            raise PageInformationError(
                f"__get_classmates中网页内容发生改变, 错误为{e}, 内容为\n{r.text}")

    def get_contact_teachers(self) -> list:  # 已重写
        """获取班级所有老师"""
        self.update_login_status()
        r = self._session.get(URLs.GET_TEACHERS_URL)
        if not r.ok:
            raise PageConnectionError(f"接口返回错误, 状态码为{r.status_code}")
        try:
            return r.json()
        except (json.JSONDecodeError, KeyError) as e:
            raise PageInformationError(f"内容发生改变, 错误为{e}, 内容为\n{r.text}")

    def get_exam_level_trend(self, exam_id: str = None, page_index: int = 1, page_size: int = 100) -> dict:  # 已重写
        """获取等级趋势
        :param exam_id: 考试id
        :param page_index: 页码 默认1
        :param page_size: 每页数量 默认100

        :return: dict"""
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


class TeacherAccount(Account):
    """老师账号"""

    def __init__(self, session):
        super().__init__(session)

    def set_base_info(self):
        self.info = self._session.get(
            url=URLs.TEST_URL,
            headers={"referer": "https://www.zhixue.com/container/container/teacher/index/"}).json()["teacher"]
        return self

    async def __get_marking_school_class(self, school_id: str, subject_id: str):
        async with httpx.AsyncClient(cookies=self._session.cookies) as client:
            r = await client.get(URLs.GET_EXAM_SCHOOLS_URL,
                                 params={"schoolId": school_id, "markingPaperId": subject_id})
            return r.json()

    def get_marking_school_class(self, school_id: str, subject_id: str):
        self.update_login_status()
        return asyncio.run(self.__get_marking_school_class(school_id, subject_id))

    def get_topic(self, user_id: str, paper_id: str, save_to_path: str = None, result_type: str = "save"):
        """
        获得原卷
        Args:
            user_id (str): 为需要查询原卷的userId
            paper_id (str): 为需要查询的学科ID(topicSetId)
            save_to_path (str): 为原卷保存位置(html文件), 精确到文件名, 默认为f"{user_id}_{paper_id}.html"
            result_type (str): 为返回类型, 可选值为"save"和"return", "save"为保存到本地, "return"为返回原卷内容
        """
        self.update_login_status()
        if save_to_path is None:
            save_to_path = f"./{user_id}_{paper_id}.html"
        req = self._session.get(URLs.ORIGINAL_PAPER_URL, params={
            "userId": user_id,
            "paperId": paper_id
        })
        if req.ok and "生成" not in req.text:
            result = req.text.replace("//static.zhixue.com", "https://static.zhixue.com")  # 替换html内容，让文件可以正常显示
            if result_type == "save":
                with open(save_to_path, encoding="utf-8", mode="w+") as fhandle:
                    fhandle.writelines(result)
                return True
            elif result_type == "return":
                return result
            else:
                raise ValueError("Argument 'type' must be 'save' or 'return'")
        else:
            raise PageInformationError("获取原卷失败")

    def get_scanrecognition(self, exam_id: str):
        """获取考试详情"""
        self.update_login_status()
        return self._session.post(URLs.GET_EXAM_DETAIL_URL, data={"examId": exam_id}).json()

    def get_marking_progress_detail(self, subject_id: str, school_id: str = ""):
        """获取批阅进度详情"""
        self.update_login_status()
        return self._session.post(URLs.GET_MARKING_PROGRESS_URL, data={
            "progressParam": json.dumps({
                "markingPaperId": subject_id,
                "topicNum": None,
                "subTopicIndex": None,
                "topicStartNum": 1,
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

    def get_one_score(self, stu_id, paper_id):
        data = self._session.get(
            url='https://www.zhixue.com/classreport/class/student/checksheet/',
            params={
                'userId': stu_id,
                'paperId': paper_id
            }
        )
        t_score = 0.0
        try:
            for i in json.loads(re.findall(r'var sheetDatas = (.*?);',
                                           data.text)[0])["userAnswerRecordDTO"]["answerRecordDetails"]:
                t_score += i["score"]
        except:
            pass
        return t_score

    def get_simple_answer_records(self,
                                  clazz_id: str, topic_set_id: str, topic_number: int = 1, _type: str = "a") -> list:
        """获取班级单题答题记录"""
        self.update_login_status()
        return self._session.get(URLs.GET_SIMPLE_ANSWER_RECORDS_URL, params={
            "classId": clazz_id,
            "topicSetId": topic_set_id,
            "topicNumber": topic_number,
            "type": _type
        }).json()

    def get_school_answer_records(self,school_id: str, topic_set_id: str, topic_number: int = 1) -> list[list]:
        """获取学校单题答题记录"""
        ret = []
        for each in self.get_marking_school_class(school_id, topic_set_id):
            ret.extend(self.get_simple_answer_records(each['classId'], topic_set_id, topic_number))  # (ret.append)
        return ret

#     def get_school_mark(self, exam_id) -> list[list[list]]:
#         """获取学校考试分数"""
#         self.update_login_status()
#         ret = []
#         for each in self.get_scanrecognition(exam_id)['result']:
#             ret.append(self.get_school_answer_records(each['id']))
#         return ret

    def get_token(self) -> str:
        if self._token is not None:
            return self._token
        self._token = self._session.get(
            "https://www.zhixue.com/container/app/token/getToken").json()["result"]
        return self._token


def load_account(path: str = "user.data") -> Account:
    with open(path, "rb") as f:
        data = base64.b64decode(f.read())
        account_data: AccountData = pickle.loads(data)
        return login(account_data.username, account_data.encoded_password)


def login(username: str, password: str, _type: str = "auto", _data: bool = True):
    """通过用户名和密码登录智学网

    Args:
        username (str): 用户名, 可以为准考证号, 手机号
        password (str): 密码(包括加密后的密码)
        _type (str, optional): 登录类型. Defaults to "auto".
        _data (str, optional): 返回的数据. Defaults to True.

    Raises:
        ArgError: 参数错误
        UsernameOrPasswordError: 用户名或密码错误
        UserNotFoundError: 未找到用户
        LoginError: 登录错误
        RoleError: 账号角色未知

    Returns:
        Person
    """
    if len(password) != 32:
        e = "010001"
        m = "008c147f73c2593cba0bd007e60a89ade5"
        keylength = rsa.common.byte_size(rsa.PublicKey(int(m, 16), int(e, 16)).n)
        padding = b''
        for i in range(keylength - len(password.encode()[::-1]) - 3):
            padding += b'\x00'
        encrypted = rsa.core.encrypt_int(rsa.transform.bytes2int(b''.join([b'\x00\x00', padding, b'\x00',
                                                                           password.encode()[::-1]])),
                                         rsa.PublicKey(int(m, 16), int(e, 16)).e,
                                         rsa.PublicKey(int(m, 16), int(e, 16)).n)
        password = rsa.transform.int2bytes(encrypted, keylength).hex()
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
            raise UsernameOrPasswordError()
        if json_obj["code"] == 2009:
            raise UserNotFoundError()
        raise LoginError(json_obj["data"])
    ticket = json_obj["data"]["st"]
    session.post(URLs.SERVICE_URL, data={"action": "login", "ticket": ticket})
    session.cookies.set("uname", base64.b64encode(username.encode()).decode())
    session.cookies.set("pwd", base64.b64encode(password.encode()).decode())
    if _data:
        if "student" in session.get("https://www.zhixue.com/container/container/index/").url:
            return StudentAccount(session).set_base_info()
        else:
            return TeacherAccount(session).set_base_info()
    return session
