BASE_DOMAIN = "zhixue.com"
BASE_URL = f"https://www.{BASE_DOMAIN}"


class Url:
    SERVICE_URL = f"{BASE_URL}:443/ssoservice.jsp"
    SSO_URL = f"https://sso.{BASE_DOMAIN}/sso_alpha/login?service={SERVICE_URL}"
    TEST_PASSWORD_URL = f"{BASE_URL}/weakPwdLogin/?from=web_login"
    TEST_URL = f"{BASE_URL}/container/container/teacher/teacherAccountNew"
    GET_LOGIN_STATE = f"{BASE_URL}/loginState/"

    # STUDENT

    INFO_URL = f"{BASE_URL}/container/container/student/account/"

    # Login
    SERVICE_URL = f"{BASE_URL}:443/ssoservice.jsp"

    CHANGE_PASSWORD_URL = f"{BASE_URL}/portalcenter/home/updatePassword/"

    # Exam
    XTOKEN_URL = f"{BASE_URL}/addon/error/book/index"
    GET_STU_EXAM_URL = f"{BASE_URL}/zhixuebao/report/exam/getUserExamList"
    GET_RECENT_EXAM_URL = f"{BASE_URL}/zhixuebao/report/exam/getRecentExam"
    # GET_MARK_URL = f"{BASE_URL}/zhixuebao/zhixuebao/feesReport/getStuSingleReportDataForPK/"
    GET_SUBJECT_URL = f"{BASE_URL}/zhixuebao/report/exam/getReportMain"
    GET_MARK_URL = GET_SUBJECT_URL
    GET_ORIGINAL_URL = f"{BASE_URL}/zhixuebao/report/checksheet/"

    # Person
    GET_CLAZZS_URL = f"{BASE_URL}/zhixuebao/zhixuebao/friendmanage/"
    # GET_CLASSMATES_URL = f"{BASE_URL}/zhixuebao/zhixuebao/getClassStudent/"
    GET_CLASSMATES_URL = f"{BASE_URL}/container/contact/student/students"
    GET_TEACHERS_URL = f"{BASE_URL}/container/contact/student/teachers"

    APP_BASE_URL = "https://mhw.zhixue.com"
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