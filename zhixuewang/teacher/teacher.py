import asyncio
import json
from typing import List
import httpx
from zhixuewang.models import (Account, Exam, ExtendedList, Role, School, Sex, StuClass, Subject)
from zhixuewang.teacher.models import (ExamMarkingProgress, SubjectMarkingProgress, TeaPerson,
                                       TopicMarkingProgress, TopicTeacherMarkingProgress)
from zhixuewang.teacher.urls import Url


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

    async def __get_school_exam_classes(self, school_id: str, subject_id: str) -> List[StuClass]:
        async with httpx.AsyncClient(cookies=self._session.cookies) as client:
            r = await client.get(Url.GET_EXAM_SCHOOLS_URL, params={
                "schoolId": school_id,
                "markingPaperId": subject_id
            })
            data = r.json()
            classes = []
            for each in data:
                classes.append(StuClass(
                    id=each["classId"],
                    name=each["className"],
                    school=School(id=each["schoolId"])
                ))
            return classes

    def get_school_exam_classes(self, school_id: str, subject_id: str) -> List[StuClass]:
        self.update_login_status()
        return asyncio.run(self.__get_school_exam_classes(school_id, subject_id))

    def get_original_paper(self,
                           userId: str, paperId: str,
                           saveToPath: str) -> bool:
        """
        获得原卷
        Args:
            userId (str): 为需要查询原卷的userId
            paperId (str): 为需要查询的学科ID(topicSetId)
            saveToPath (str): 为原卷保存位置(html文件), 精确到文件名
        Return:
            bool: 正常会返回True
        """
        data = self._session.get(Url.ORIGINAL_PAPER_URL, params={
            "userId": userId,
            "paperId": paperId
        })
        with open(saveToPath, encoding="utf-8", mode="w+") as fhandle:
            # 替换html内容，让文件可以正常显示
            fhandle.writelines(data.text.replace(
                "//static.zhixue.com", "https://static.zhixue.com"))
        return True

    def get_exam_subjects(self, exam_id: str) -> ExtendedList[Subject]:
        self.update_login_status()
        r = self._session.get(Url.GET_EXAM_SUBJECTS_URL, params={
            "examId": exam_id
        })
        data = r.json()["result"]
        subjects = []
        for each in data:
            name = each["subjectName"]
            if name != "总分" and (not each.get("isSubjectGroup")):  # 排除学科组()
                subjects.append(Subject(
                    id=each["topicSetId"],
                    name=each["subjectName"],
                    code=each["subjectCode"],
                    standard_score=each["standScore"]
                ))
        return ExtendedList(sorted(subjects, key=lambda x: x.code, reverse=False))

    def get_exam_detail(self, exam_id: str) -> Exam:
        self.update_login_status()
        r = self._session.post(Url.GET_EXAM_DETAIL_URL, data={
            "examId": exam_id
        })
        data = r.json()["result"]
        exam = Exam()
        schools: ExtendedList[School] = ExtendedList()
        for each in data["schoolList"]:
            schools.append(School(
                id=each["schoolId"],
                name=each["schoolName"]
            ))
        exam.id = exam_id
        exam.name = data["exam"]["examName"]
        exam.grade_code = data["exam"]["gradeCode"]

        isCrossExam = data["exam"]["isCrossExam"]
        exam.schools = schools
        exam.status = str(isCrossExam)
        exam.subjects = self.get_exam_subjects(exam_id)
        return exam

    @staticmethod
    def _parse_marking_progress_data(r, subject_id: str):
        data = r.json()["message"]
        progress_data = []
        for each in json.loads(data):
            topic_progress_data = TopicMarkingProgress(
                disp_title=each["dispTitle"],
                topic_number=each["topicNum"],
                complete_precent=each["completeRate"],
                subject_id=subject_id
            )
            for each2 in each["teacherList"]:
                topic_progress_data.teachers.append(TopicTeacherMarkingProgress(
                    teacher_name=each2["name"],
                    school=School(
                        id=each2["schoolId"],
                        name=each2["schoolName"]
                    ),
                    is_online=each2["isOnline"],
                    teacher_code=each2["code"],
                    complete_count=each2["completeCount"],
                    uncomplete_count=each2["arUncompleteCount"]
                ))
            progress_data.append(topic_progress_data)
        return progress_data

    def get_marking_progress(self, subject_id: str, school_id: str = "") -> List[TopicMarkingProgress]:
        r = self._session.post(Url.GET_MARKING_PROGRESS_URL, data={
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
        # return r.json()
        return self._parse_marking_progress_data(r, subject_id)

    async def _get_marking_progress_async(self, subject_id: str, school_id: str):
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
            return self._parse_marking_progress_data(r, subject_id)

    def get_token(self) -> str:
        if self._token is not None:
            return self._token
        r = self._session.get(
            "https://www.zhixue.com/container/app/token/getToken")
        self._token = r.json()["result"]
        return self._token

    def get_headers(self):
        return {"token": self.get_token()}

    async def _get_exam_all_marking_progress(self, exam: Exam) -> ExamMarkingProgress:
        tasks = []
        for subject in exam.subjects:
            for school in exam.schools:
                tasks.append(self._get_marking_progress_async(
                    subject.id, school.id))
        result = await asyncio.gather(*tasks)
        examMarkingProgress = ExamMarkingProgress(exam)
        for each in result:
            examMarkingProgress.markingProgresses.append(SubjectMarkingProgress(
                subject=exam.subjects.find_by_id(
                    each[0].subject_id),  # type: ignore
                markingProgresses=each
            ))
        return examMarkingProgress

    def get_exam_all_marking_progress(self, exam_id: str) -> ExamMarkingProgress:
        exam = self.get_exam_detail(exam_id)
        return asyncio.run(self._get_exam_all_marking_progress(exam))
