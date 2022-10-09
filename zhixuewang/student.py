import hashlib
import time
import uuid
from zhixuewang.models import (Account, Role, StuClass, School, Sex, Grade, Phase, StuPerson)
from zhixuewang.exceptions import UserDefunctError, PageConnectionError, PageInformationError
from zhixuewang.urls import Url
from json import JSONDecodeError


def _check_is_uuid(msg: str):
    """判断msg是否为uuid"""
    return len(msg) == 36 and msg[14] == "4" and msg[8] == msg[13] == msg[18] == msg[23] == "-"


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
        r = self._session.get(Url.XTOKEN_URL, headers={
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
        r = self._session.get(Url.INFO_URL)
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
        r = self._session.get(Url.INFO_URL)
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

    def get_page_exam(self, page_index: int = 1, page_size: int = 10) -> dict:  # 已重写
        """获取指定页数的考试列表"""
        self.update_login_status()
        r = self._session.get(Url.GET_STU_EXAM_URL,
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
        r = self._session.get(Url.GET_RECENT_EXAM_URL,
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
            cur_exams = self.get_page_exam(i, 100)
            exams.extend(cur_exams['result']['examList'])
            check = cur_exams['result']['hasNextPage']
            i += 1
        return exams

    def get_report_main(self, exam: str = None) -> dict:  # 已重写
        self.update_login_status()
        if not exam:
            exam = self.get_recent_exam()["result"]["examInfo"]["examId"]
        r = self._session.get(Url.GET_MARK_URL,
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
        r = self._session.get(Url.GET_ORIGINAL_URL,
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
        r = self._session.get(Url.GET_CLAZZS_URL,
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
        r = self._session.get(Url.GET_CLASSMATES_URL,
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

    def get_exam_level_trend(self, exam_id: str = None, page_index: int = 1, page_size: int = 100) -> dict:  # 已重写
        """获取等级趋势"""
        if exam_id is None:
            exam_id = self.get_recent_exam()["result"]["examInfo"]["examId"]
        self.update_login_status()
        r = self._session.get(Url.GET_EXAM_LEVEL_TREND_URL, params={
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
        r = self._session.get(Url.GET_SUBJECT_DIAGNOSIS, params={
            "examId": exam_id
        }, headers=self._get_auth_header())
        if r.ok:
            return r.json()
