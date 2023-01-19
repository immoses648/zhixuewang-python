import base64
import hashlib
import json
import re
import time
import uuid

import requests
import rsa.common
import rsa.core
import rsa.transform


# URLS
class URLs:
    base_domain = "zhixue.com"
    base = f"https://www.{base_domain}"
    sso_service = f"{base}:443/ssoservice.jsp"
    sso = f"https://sso.{base_domain}/sso_alpha/login?service={sso_service}"
    login_state = f"{base}/loginState/"

    # STUDENT
    stu_info = f"{base}/container/container/student/account/"
    stu_exams = f"{base}/zhixuebao/report/exam/getUserExamList"
    stu_checksheet = f"{base}/zhixuebao/report/checksheet/"
    xtoken = f"{base}/addon/error/book/index"
    clazzs = f"{base}/zhixuebao/zhixuebao/friendmanage/"
    classmates = f"{base}/container/contact/student/students"
    teachers = f"{base}/container/contact/student/teachers"
    recent_exam = f"{base}/zhixuebao/report/exam/getRecentExam"
    exam_report = f"{base}/zhixuebao/report/exam/getReportMain"
    exam_level_trend = f"{base}/zhixuebao/report/exam/getLevelTrend"
    subject_diagnosis = f"{base}/zhixuebao/report/exam/getSubjectDiagnosis"

    # TEACHER
    tch_info = f"{base}/container/container/teacher/teacherAccountNew"
    tch_exams = f"{base}/api-classreport/class/classReportList/"
    tch_checksheet = f"{base}/classreport/class/student/checksheet/"
    exam_detail = f"{base}/scanmuster/cloudRec/scanrecognition"
    exam_clazzs = f"{base}/exam/marking/schoolClass"
    # clazz_topic_detail = f"{base}/commonment/class/getClassTopicDetailWithNoTopic"
    # ?markingPaperTopicId=&classId=&topicSetId=&topicTypeId=01&paperType=a
    # typical_paper = f"{base}/commonment/class/getTypicalPaper"
    # ?topicSetId=&classId=&topicId=&topicNumber=
    simple_answer_records = f"{base}/commonment/class/getSimpleAnswerRecords/"
    stu_exam_detail = f"{base}/freshprecisionapi/studentLiteracy/getStuExamDetail"


class Account:
    def __init__(self, session):
        self._session = session
        self._auth = {'token': None, 'timestamp': 0.0}
        self.info = None

    def request_api(
            self,
            url: str,
            params: dict = None,
            headers=None,
            headers_required: bool = False,
            check: bool = False,
            return_json: bool = True):
        if not self._session.get(URLs.login_state).json()["result"] == "success":  # 检查登录状态
            self._session = login(
                username=self.info['loginName'],
                password=base64.b64decode(self._session.cookies["pwd"].encode()).decode())._session
        if headers_required:  # （学生）如果需要headers就获取
            auth_guid = str(uuid.uuid4())
            auth_time_stamp = str(int(time.time() * 1000))
            md5 = hashlib.md5()
            md5.update((auth_guid + auth_time_stamp + "iflytek!@#123student").encode(encoding="utf-8"))
            auth_token = md5.hexdigest()
            if not self._auth['token'] or (time.time() - self._auth['timestamp']) >= 600:  # 判断token是否过期
                self._auth['token'] = self.request_api(URLs.xtoken, headers={
                    "authbizcode": "0001",
                    "authguid": auth_guid,
                    "authtimestamp": auth_time_stamp,
                    "authtoken": auth_token
                }, check=True)
                self._auth['timestamp'] = time.time()
            headers = {
                "authbizcode": "0001",
                "authguid": auth_guid,
                "authtimestamp": auth_time_stamp,
                "authtoken": auth_token,
                "XToken": self._auth['token']
            }
        req = self._session.get(url=url, params=params, headers=headers)
        if req.status_code != 200 or not req.ok:
            raise ValueError(
                "No Permission."
            ) if req.status_code == 500 else RuntimeError(
                f"Request Error: {req.status_code}/{req.text}"
            )
        if check:
            try:
                if req.json()['errorCode'] != 0:
                    raise ValueError(f"API Error: {req.json()['errorCode']}/{req.text}")
                return req.json()['result'] if return_json else req
            except (json.JSONDecodeError, KeyError) as e:
                raise RuntimeError(f'API Error: {req.status_code}/{req.text}/{e}')
        return req.json() if return_json else req


# MAIN CLASSES
class StudentAccount(Account):
    """学生账号"""

    def set_base_info(self):
        """设置账户基本信息"""
        json_data = self.request_api(URLs.stu_info)["student"]
        if not json_data.get("clazz", False):
            raise ValueError("账号已失效")
        self.info = json_data
        return self

    def get_exam_list(self, page_index: int = 1, page_size: int = 10) -> dict:
        """获取考试列表"""
        return self.request_api(
            URLs.stu_exams,
            params={"pageIndex": page_index, "pageSize": page_size},
            headers_required=True, check=True)

    def get_recent_exam(self) -> dict:
        """获取最新考试"""
        return self.request_api(URLs.recent_exam, headers_required=True, check=True)

    def get_exams(self) -> list:
        """获取所有考试"""
        i = 1
        check = True
        exams = []
        while check:
            cur_exams = self.get_exam_list(i, 100)
            exams.extend(cur_exams['examList'])
            check = cur_exams['hasNextPage']
            i += 1
        return exams

    def get_exam_report(self, exam: str = None) -> dict:
        """获取考试报告"""
        return self.request_api(
            URLs.exam_report,
            params={"examId": self.get_recent_exam()["examInfo"]["examId"] if exam is None else exam},
            headers_required=True,
            check=True
        )

    def get_checksheet(self, subject_id: str, exam_id=None):
        """（学生）获取原卷"""
        return self.request_api(
            URLs.stu_checksheet,
            params={
                "examId": self.get_recent_exam()["examInfo"]["examId"] if exam_id is None else exam_id,
                "paperId": subject_id},
            headers_required=True)

    def get_clazzs(self):
        """获取当前年级所有班级"""
        return self.request_api(URLs.clazzs, params={"d": int(time.time())})

    def get_classmates(self, clazz_id: str = None) -> list:
        """获取班级所有学生"""
        return self.request_api(
            URLs.classmates,
            params={
                "r": f"{self.info['id']}student",
                "clazzId": self.info["clazz"]["id"] if clazz_id is None else clazz_id
            }
        )

    def get_teachers(self) -> list:
        """获取班级所有老师"""
        return self.request_api(URLs.teachers)

    def get_exam_level_trend(self, exam_id: str = None, page_index: int = 1, page_size: int = 100) -> dict:
        """获取考试等级趋势"""
        return self.request_api(
            URLs.exam_level_trend,
            params={
                "examId": self.get_recent_exam()["examInfo"]["examId"] if exam_id is None else exam_id,
                "pageIndex": page_index,
                "pageSize": page_size
            },
            headers_required=True,
            check=True
        )

    def get_subject_diagnosis(self, exam_id: str = None) -> dict:
        """获取科目诊断"""
        return self.request_api(
            URLs.subject_diagnosis,
            params={"examId": self.get_recent_exam()["examInfo"]["examId"] if exam_id is None else exam_id},
            headers_required=True,
            check=True
        )


class TeacherAccount(Account):
    """老师账号"""

    def set_base_info(self):
        self.info = self.request_api(
            URLs.tch_info,
            headers={"referer": "https://www.zhixue.com/container/container/teacher/index/"})["teacher"]
        return self

    def get_exam_clazzs(self, school_id: str, subject_id: str):
        """获取某校中参与考试的班级（无鉴权）"""
        return self.request_api(URLs.exam_clazzs, params={"schoolId": school_id, "markingPaperId": subject_id})

    def get_exams(
            self, start_time=None, end_time=None, exam_name: str = None, grade_code="all",
            class_id="all", subject_code="all", search_type="schoolYearType", circles_year=None,
            exam_type_code="all", term_id=None, teaching_cycle_id=None,
            page_size=100, page_index=1) -> dict:
        """获取教师报告列表（强鉴权）"""
        return self.request_api(URLs.tch_exams, params={
            "examName": exam_name,
            "gradeCode": grade_code,
            "classId": class_id,
            "subjectCode": subject_code,
            "searchType": search_type,
            "circlesYear": circles_year,
            "examTypeCode": exam_type_code,
            "termId": term_id,
            "teachingCycleId": teaching_cycle_id,
            "startTime": start_time,
            "endTime": end_time,
            "pageSize": page_size,
            "pageIndex": page_index,
            "t": int(time.time())
        })

    def get_checksheet(self, user_id: str, paper_id: str, save_to_path: str = None, ret: bool = False):
        """
        获得原卷（普通鉴权）
        Args:
            user_id (str): 学生的userId
            paper_id (str): 试卷的topicSetId
            save_to_path (str): 为原卷保存位置(html文件), 精确到文件名, 默认为f"{user_id}_{paper_id}.html"
            ret (bool): 为返回类型, False为保存到本地, True为直接返回原卷内容
        """
        result = self.request_api(
            URLs.tch_checksheet,
            params={"userId": user_id, "paperId": paper_id},
            return_json=False
        ).text.replace("//static.zhixue.com", "https://static.zhixue.com")  # 替换html内容，让文件可以正常显示
        if ret:
            return result
        with open(
                f"{user_id}_{paper_id}.html" if save_to_path is None else save_to_path,
                encoding="utf-8",
                mode="w+") as fhandle:
            fhandle.writelines(result)
        return

    def get_checksheet_datas(self, user_id: str, paper_id: str):
        """获得原卷中的数据（包括答题卡裁切定位信息、题目信息及阅卷情况等）（普通鉴权）"""
        return json.loads(re.findall(
            r'var sheetDatas = (.*?);',
            self.request_api(
                URLs.tch_checksheet,
                params={'userId': user_id, 'paperId': paper_id},
                return_json=False
            ).text)[0])

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

    def get_stu_exam_detail(self, subject_id, clazz_id, stu_id, time_id=None, exam_type=None, clazz_type="1"):
        """获取学生某科目往次考试详情（强鉴权）"""
        return self.request_api(
            URLs.stu_exam_detail,
            params={"userId": self.info['id'],
                    "subjectId": subject_id,
                    "timeId": "2022-2023,"
                              "2021-2022,"
                              "2020-2021,"
                              "2019-2020,"
                              "2018-2019,"
                              "2017-2018,"
                              "2016-2017,"
                              "2015-2016,"
                              "2014-2015"
                    if time_id is None else time_id,
                    "classId": clazz_id,
                    "stuId": stu_id,
                    "examType": "midtermExam,"
                                "terminalExam,"
                                "weeklyExam,"
                                "monthlyExam,"
                                "unifiedExam,"
                                "homework,"
                                "limitedTimeWork,"
                                "mockExam" if exam_type is None else exam_type,
                    "classType": clazz_type,
                    "t": int(time.time())}
        )


def login(username: str, password: str, _type: str = "auto"):
    """使用账号密码登录

    Args:
        username (str): Username or 准考证号
        password (str): Password (also accept encrypted password)
        _type (str, optional): the type of the value of username. Defaults to "auto".

    """
    if len(password) != 32:
        e = "010001"
        m = "008c147f73c2593cba0bd007e60a89ade5"
        keylength = rsa.common.byte_size(rsa.PublicKey(int(m, 16), int(e, 16)).n)
        padding = b''
        for i in range(keylength - len(password.encode()[::-1]) - 3):
            padding += b'\x00'
        encrypted = rsa.core.encrypt_int(
            rsa.transform.bytes2int(b''.join([b'\x00\x00', padding, b'\x00', password.encode()[::-1]])),
            rsa.PublicKey(int(m, 16), int(e, 16)).e,
            rsa.PublicKey(int(m, 16), int(e, 16)).n)
        password = rsa.transform.int2bytes(encrypted, keylength).hex()
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1"
    json_obj = json.loads(session.get(URLs.sso).text.strip().replace("\\", "").replace("'", "")[1:-1])
    if json_obj["code"] != 1000:
        raise RuntimeError(f'An error occured when login:{json_obj["code"]}/{json_obj["data"]}')
    r = session.get(
        URLs.sso,
        params={
            "encode": "true",
            "sourceappname": "tkyh,tkyh",
            "_eventId": "submit",
            "appid": "zx-container-client",
            "client": "web",
            "type": "loginByNormal",
            "key": _type,
            "lt": json_obj["data"]["lt"],
            "execution": json_obj["data"]["execution"],
            "customLogoutUrl": "https://www.zhixue.com/login.html",
            "username": username,
            "password": password
        })
    json_obj = json.loads(r.text.strip().replace("\\", "").replace("'", "")[1:-1])
    if json_obj["code"] != 1001:
        if json_obj["code"] == 1002:
            raise ValueError("Incorrect username and password")
        if json_obj["code"] == 2009:
            raise ValueError("Account does not exist")
        raise RuntimeError(f'An error occured when login:{json_obj["code"]}/{json_obj["data"]}')
    session.post(URLs.sso_service, data={"action": "login", "ticket": json_obj["data"]["st"]})
    session.cookies.set("uname", base64.b64encode(username.encode()).decode())
    session.cookies.set("pwd", base64.b64encode(password.encode()).decode())
    req_check_type = session.get("https://www.zhixue.com/container/container/index/").url
    if "student" in req_check_type:
        return StudentAccount(session).set_base_info()
    elif "teacher" in req_check_type:
        return TeacherAccount(session).set_base_info()
    else:
        raise ValueError("Unsupport account type")
