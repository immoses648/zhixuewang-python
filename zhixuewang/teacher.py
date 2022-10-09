import asyncio
import json
from typing import List
import httpx
from zhixuewang.models import (Account, Role, Sex, StuClass, TeaPerson)
from zhixuewang.urls import Url


class TeacherAccount(Account, TeaPerson):
    """老师账号"""

    def __init__(self, session):
        super().__init__(session, Role.teacher)
        self._token = None

    def set_base_info(self):
        r = self._session.get(
            Url.TEST_URL,
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
            r = await client.get(Url.GET_EXAM_SCHOOLS_URL, params={
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
        data = self._session.get(Url.ORIGINAL_PAPER_URL, params={
            "userId": user_id,
            "paperId": paper_id
        })
        with open(save_to_path, encoding="utf-8", mode="w+") as fhandle:
            # 替换html内容，让文件可以正常显示
            fhandle.writelines(data.text.replace(
                "//static.zhixue.com", "https://static.zhixue.com"))

    def get_subjects_include_sub_and_group(self, exam_id: str):
        self.update_login_status()
        r = self._session.get(Url.GET_EXAM_SUBJECTS_URL, params={
            "examId": exam_id
        })
        return r.json()

    def get_scanrecognition(self, exam_id: str):
        """获取考试详情"""
        self.update_login_status()
        r = self._session.post(Url.GET_EXAM_DETAIL_URL, data={
            "examId": exam_id
        })
        return r.json()

    def get_marking_progress_detail(self, subject_id: str, school_id: str = ""):
        return self._session.post(Url.GET_MARKING_PROGRESS_URL, data={
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
            r = await client.post(Url.GET_MARKING_PROGRESS_URL, data={
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
