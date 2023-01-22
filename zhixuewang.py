import re
import json
import time
import uuid
import base64
from hashlib import md5

import requests


# URLS
class URLs:
    # BASE
    base_domain = "zhixue.com"
    base = f"https://www.{base_domain}"

    # LOGIN
    sso_service = f"{base}:443/ssoservice.jsp"
    sso = f"https://sso.{base_domain}/sso_alpha/login?service={sso_service}"
    login_state = f"{base}/loginState/"

    container = f"{base}/container"
    zhixuebao = f"{base}/zhixuebao"

    # STUDENT
    stu_info = f"{container}/container/student/account/"
    stu_exams = f"{zhixuebao}/report/exam/getUserExamList"
    stu_checksheet = f"{zhixuebao}/report/checksheet/"
    xtoken = f"{base}/addon/error/book/index"
    clazzs = f"{zhixuebao}/zhixuebao/friendmanage/"
    classmates = f"{container}/contact/student/students"
    teachers = f"{container}/contact/student/teachers"
    recent_exam = f"{zhixuebao}/report/exam/getRecentExam"
    exam_report = f"{zhixuebao}/report/exam/getReportMain"
    exam_level_trend = f"{zhixuebao}/report/exam/getLevelTrend"
    subject_diagnosis = f"{zhixuebao}/report/exam/getSubjectDiagnosis"

    # TEACHER
    tch_info = f"{container}/container/teacher/teacherAccountNew"
    tch_checksheet = f"{base}/classreport/class/student/checksheet/"
    exam_detail = f"{base}/scanmuster/cloudRec/scanrecognition"
    exam_clazzs = f"{base}/exam/marking/schoolClass"
    simple_answer_records = f"{base}/commonment/class/getSimpleAnswerRecords/"


class Account:
    def __init__(self, session: requests.Session):
        self._session: requests.Session = session
        self._info: dict = {}
        self._auth: dict = {'token': None, 'timestamp': 0.0}

    def request_api(
            self,
            url: str,
            params: dict = None,
            headers: dict = None,
            check: bool = False,
            return_json: bool = True
    ):
        if not self._session.get(URLs.login_state).json()["result"] == "success":  # 检查登录状态
            self._session = login(username=base64.b64decode(self._session.cookies["uname"].encode()).decode(),
                                  password=base64.b64decode(self._session.cookies["pwd"].encode()).decode())._session
        req = self._session.get(url=url, params=params, headers=headers)
        if req.status_code != 200 or not req.ok:
            if req.status_code == 500:
                raise ValueError("No Permission.")
            RuntimeError(f"Request Error {req.status_code}: {req.text}")
        if check:
            try:
                if req.json()['errorCode'] != 0:
                    raise ValueError(f"API Error {req.json()['errorCode']}: {req.text}")
                return req.json()['result'] if return_json else req
            except (json.JSONDecodeError, KeyError) as e:
                raise RuntimeError(f'API Error {req.status_code}: {req.text}/{e}')
        return req.json() if return_json else req


class StudentAccount(Account):
    """学生账号"""

    def __init__(self, session):
        super().__init__(session=session)

    @property
    def info(self) -> dict:
        """获取个人信息"""
        if self._info == {}:
            self._info = self.request_api(URLs.stu_info)["student"]
        return self._info

    @property
    def headers(self) -> dict:
        """获取headers"""
        guid = str(uuid.uuid4())
        timestamp = str(int(time.time() * 1000))
        headers = {
            "authbizcode": "0001",
            "authguid": guid,
            "authtimestamp": timestamp,
            "authtoken": md5((guid + timestamp + "iflytek!@#123student").encode(encoding="utf-8")).hexdigest()
        }
        if not self._auth['token'] or (time.time() - self._auth['timestamp']) >= 600:  # 判断token是否过期
            self._auth = {
                'token': self.request_api(URLs.xtoken, headers=headers, check=True),
                'timestamp': time.time()
            }
        headers['XToken'] = self._auth['token']
        return headers

    @property
    def teachers(self) -> list:
        """获取班级所有老师"""
        return self.request_api(URLs.teachers)

    @property
    def recent_exam(self) -> dict:
        """获取最新考试"""
        return self.request_api(URLs.recent_exam, headers=self.headers, check=True)

    @property
    def exams(self) -> list:
        """获取所有考试"""
        i = 1
        check = True
        exams = []
        while check:
            cur_exams = self.get_exam_list(i, 10000)
            exams.extend(cur_exams['examList'])
            check = cur_exams['hasNextPage']
            i += 1
        return exams

    @property
    def clazzs(self) -> list:
        """获取当前年级所有班级"""
        return self.request_api(URLs.clazzs, params={"d": int(time.time())})['clazzs']

    def get_exam_list(self, page_index: int = 1, page_size: int = 10) -> dict:
        """获取考试列表"""
        return self.request_api(
            URLs.stu_exams,
            params={"pageIndex": page_index, "pageSize": page_size},
            headers=self.headers,
            check=True
        )

    def get_exam_report(self, exam_id: str = None) -> dict:
        """获取考试报告"""
        return self.request_api(
            URLs.exam_report,
            params={"examId": self.recent_exam["examInfo"]["examId"] if exam_id is None else exam_id},
            headers=self.headers,
            check=True
        )

    def get_checksheet(self, topic_set_id: str, exam_id=None):
        """（学生）获取原卷"""
        return self.request_api(
            URLs.stu_checksheet,
            params={
                "examId": self.recent_exam["examInfo"]["examId"] if exam_id is None else exam_id,
                "paperId": topic_set_id
            },
            headers=self.headers
        )

    def get_classmates(self, clazz_id: str = None) -> list:
        """获取班级所有学生"""
        return self.request_api(
            URLs.classmates,
            params={
                "r": f"{self.info['id']}student",
                "clazzId": self.info["clazz"]["id"] if clazz_id is None else clazz_id,
            }
        )

    def get_exam_level_trend(self, exam_id: str = None, page_index: int = 1, page_size: int = 100) -> dict:
        """获取考试等级趋势"""
        return self.request_api(
            URLs.exam_level_trend,
            params={
                "examId": self.recent_exam["examInfo"]["examId"] if exam_id is None else exam_id,
                "pageIndex": page_index,
                "pageSize": page_size,
            },
            headers=self.headers,
            check=True
        )

    def get_subject_diagnosis(self, exam_id: str = None) -> dict:
        """获取科目诊断"""
        return self.request_api(
            URLs.subject_diagnosis,
            params={"examId": self.recent_exam["examInfo"]["examId"] if exam_id is None else exam_id},
            headers=self.headers,
            check=True
        )


class TeacherAccount(Account):
    """老师账号"""

    def __init__(self, session):
        super().__init__(session=session)

    @property
    def info(self):
        if self._info == {}:
            self._info = self.request_api(URLs.tch_info)['teacher']
        return self._info

    def get_exam_clazzs(self, school_id: str, topic_set_id: str):
        """获取某校中参与考试的班级（无鉴权）"""
        return self.request_api(URLs.exam_clazzs, params={"schoolId": school_id, "markingPaperId": topic_set_id})

    def get_checksheet(self, user_id: str, topic_set_id: str, save_to_path: str = None, ret: bool = False):
        """
        获得原卷（普通鉴权）
        Args:
            user_id (str): 学生的userId
            topic_set_id (str): 试卷的topicSetId
            save_to_path (str): 为原卷保存位置(html文件), 精确到文件名, 默认为f"{user_id}_{paper_id}.html"
            ret (bool): 为返回类型, False为保存到本地, True为直接返回原卷内容
        """
        result = self.request_api(
            URLs.tch_checksheet,
            params={"userId": user_id, "paperId": topic_set_id},
            return_json=False
        ).text.replace("//static." + URLs.base_domain, "https://static." + URLs.base_domain)  # 替换协议头让文件正常显示
        if ret:
            return result
        with open(
                f"{user_id}_{topic_set_id}.html" if save_to_path is None else save_to_path,
                encoding="utf-8",
                mode="w+") as fhandle:
            fhandle.writelines(result)
        return

    def get_checksheet_datas(self, user_id: str, topic_set_id: str):
        """获得原卷中的数据（包括答题卡裁切定位信息、题目信息及阅卷情况等）（普通鉴权）"""
        return json.loads(re.search(
            r'var sheetDatas = (.*?);',
            self.get_checksheet(user_id, topic_set_id, ret=True)
        ).group(1))

    def get_exam_detail(self, exam_id: str):
        """获取考试详情（无鉴权）"""
        return self.request_api(URLs.exam_detail, params={"examId": exam_id}, check=True)

    def get_simple_answer_records(
            self, clazz_id: str, topic_set_id: str, topic_number: int = 1, _type: str = "a"
    ) -> list:
        """获取班级单题答题记录（普通鉴权）"""
        return self.request_api(
            URLs.simple_answer_records,
            params={"classId": clazz_id, "topicSetId": topic_set_id, "topicNumber": topic_number, "type": _type}
        )


def login(username: str, password: str) -> StudentAccount | TeacherAccount:
    """使用账号和密码登录"""
    session = requests.Session()
    password = pow(
        int.from_bytes(password.encode()[::-1], "big"), 65537, 186198350384465244738867467156319743461
    ).to_bytes(16, "big").hex() if len(password) != 32 else password  # password使用Python纯原生库进行加密
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1"
    sso_req = json.loads(session.get(URLs.sso).text.strip().replace("\\", "").replace("'", "")[1:-1])
    if sso_req["code"] != 1000:
        raise RuntimeError(f'{sso_req["code"]} error occured when login: {sso_req["data"]}')
    sso_req = json.loads(session.get(URLs.sso, params={
        "encode": "true",  # 如果false或不传encode这个参数就明文密码，true就传加密后的密码
        "_eventId": "submit",
        "appid": "zx-container-client",
        "lt": sso_req["data"]["lt"],
        "execution": sso_req["data"]["execution"],
        "username": username,
        "password": password
    }).text.strip().replace("\\", "").replace("'", "")[1:-1])
    if sso_req["code"] != 1001:
        if sso_req["code"] == 1002:
            raise ValueError("1002: Incorrect username and password")
        if sso_req["code"] == 2009:
            raise ValueError("2009: Account does not exist")
        raise RuntimeError(f'{sso_req["code"]}: {sso_req["data"]}')
    session.post(URLs.sso_service, data={"action": "login", "ticket": sso_req["data"]["st"]})
    session.cookies.set("uname", base64.b64encode(username.encode()).decode())
    session.cookies.set("pwd", base64.b64encode(password.encode()).decode())
    check_type_req = session.get(URLs.container + "/container/index/").url
    if "student" in check_type_req:
        return StudentAccount(session)
    elif "teacher" in check_type_req:
        return TeacherAccount(session)
    else:
        raise ValueError("Unsupport account type")
