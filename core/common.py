#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : su18
# @Copyright : phoebebuffayfan9527@gmail.com
# @Time  : 2019-07-16 13:33
# @FileName: common.py

import re
import random
import string
from functools import reduce
from core.data import byz
from core.data import conf
from core.data import queries
from core.data import logger
from difflib import SequenceMatcher
import lxml.html.soupparser as soupparser


def check_page_similarity(page, ori_page='original'):
    """
    检查页面相似度主函数, 利用原响应 DOM 结构及清理动态内容后的字符串比较进行判定
    :param page:
    :param ori_page:
    :return:ret_val 为 True 时，判断页面相同，为 False 时，判断页面不同
    """
    page_text_1 = queries[page]['text']
    page_static_text_1 = queries[page]['static_text']

    page_text_2 = queries[ori_page]['text']
    page_static_text_2 = byz.original_page if ori_page == 'original' else queries[ori_page]['static_text']

    if check_dom_similarity(page_text_1, page_text_2) < 0.5:
        ret_val = False
    else:
        ratio = SequenceMatcher(None, page_static_text_1, page_static_text_2).quick_ratio()
        ret_val = True if ratio > 0.98 else False
    return ret_val


def lcs(a, b):
    c = [[0 for i in range(len(b) + 1)] for j in range(len(a) + 1)]
    for i in range(len(a)):
        for j in range(len(b)):
            if a[i] == b[j]:
                c[i + 1][j + 1] = c[i][j] + 1
            elif c[i + 1][j] > c[i][j + 1]:
                c[i + 1][j + 1] = c[i + 1][j]
            else:
                c[i + 1][j + 1] = c[i][j + 1]
    return c, c[len(a)][len(b)]


def get_dom_tree(html):
    dom = soupparser.fromstring(html)
    for child in dom.iter():
        yield child.tag


def check_dom_similarity(raw_1, raw_2):
    """
    检查 DOM 树结构相似度
    :param raw_1:
    :param raw_2:
    :return:
    """

    dom_tree1 = ">".join(list(filter(lambda e: isinstance(e, str), list(get_dom_tree(raw_1)))))
    dom_tree2 = ">".join(list(filter(lambda e: isinstance(e, str), list(get_dom_tree(raw_2)))))
    c_c, length = lcs(dom_tree1, dom_tree2)
    return 2.0 * length / (len(dom_tree1) + len(dom_tree2))


def html_unescape(value):
    """
    HTML 实体编码还原
    :param value:
    :return:
    """
    _value = value
    if value and isinstance(value, str):
        codes = (('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&nbsp;', ' '), ('&amp;', '&'))
        _value = reduce(lambda x, y: x.replace(y[0], y[1]), codes, _value)
        try:
            _value = re.sub(r"&#x([^;]+);", lambda match: chr(int(match.group(1), 16)), _value)
        except ValueError:
            pass
    return _value


def filter_page_content(page, only_text=True):
    """
    移除页面中的 script/style/注释 以及其他 html 标签
    Returns filtered page content without script, style and/or comments
    or all HTML tags
    """

    ret_val = page
    if isinstance(page, str):
        ret_val = re.sub(
            r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>%s" % (r"|<[^>]+>|\t|\n|\r" if only_text else ""),
            " ", page)
        while ret_val.find("  ") != -1:
            ret_val = ret_val.replace("  ", " ")
        ret_val = html_unescape(ret_val.strip())

    return ret_val


def find_dynamic_content(first_page, second_page):
    """
    检查两个页面中存在的不同部分，并进行标记，存储到 byz.dynamic_markings
    :param first_page:
    :param second_page:
    :return:
    """

    blocks = SequenceMatcher(None, first_page, second_page).get_matching_blocks()

    # 删除过小的匹配块
    for block in blocks[:]:
        (_, _, length) = block

        if length <= 32:
            blocks.remove(block)

    # 基于前缀/后缀的原则进行动态标记
    if len(blocks) > 0:
        blocks.insert(0, None)
        blocks.append(None)

        for i in range(len(blocks) - 1):
            prefix = first_page[blocks[i][0]:blocks[i][0] + blocks[i][2]] if blocks[i] else None
            suffix = first_page[blocks[i + 1][0]:blocks[i + 1][0] + blocks[i + 1][2]] if blocks[i + 1] else None

            if prefix is None and blocks[i + 1][0] == 0:
                continue

            if suffix is None and (blocks[i][0] + blocks[i][2] >= len(first_page)):
                continue

            def trim_alpha_num(value):
                """
                从给定的位置修剪字符串
                :param value:
                :return:
                """
                while value and value[-1].isalnum():
                    value = value[:-1]
                while value and value[0].isalnum():
                    value = value[1:]
                return value

            prefix = trim_alpha_num(prefix)
            suffix = trim_alpha_num(suffix)

            byz.dynamic_markings.append((prefix[-32 // 2:] if prefix else None, suffix[:32 // 2] if suffix else None))


def remove_dynamic_content(page):
    """
    根据全局变量中的标记移除动态数据
    :param page:
    :return:
    """

    if page:
        for item in byz.dynamic_markings:
            prefix, suffix = item

            if prefix is None and suffix is None:
                continue
            elif prefix is None:
                page = re.sub(r'(?s)^.+%s' % re.escape(suffix), suffix.replace('\\', r'\\'), page)
            elif suffix is None:
                page = re.sub(r'(?s)%s.+$' % re.escape(prefix), prefix.replace('\\', r'\\'), page)
            else:
                page = re.sub(r'(?s)%s.+%s' % (re.escape(prefix), re.escape(suffix)),
                              '%s%s' % (prefix.replace('\\', r'\\'), suffix.replace('\\', r'\\')), page)

    return page


def random_int(length=4):
    """
    根据传入长度生成随机数字
    :param length:
    :return:
    """
    choice = random.choice
    return int("".join(choice(string.digits if _ != 0 else string.digits.replace('0', '')) for _ in range(0, length)))


def random_str(length=4, lowercase=False, alphabet=None):
    """
    根据传入长度生成随机字符串
    :param length:
    :param lowercase:
    :param alphabet:
    :return:
    """
    if alphabet:
        ret_val = "".join(random.choice(alphabet) for _ in range(0, length))
    elif lowercase:
        ret_val = "".join(random.choice(string.ascii_lowercase) for _ in range(0, length))
    else:
        ret_val = "".join(random.choice(string.ascii_letters) for _ in range(0, length))

    return ret_val


def get_payload_url(full_params, payload, ori_value=None):
    """
    拼接 payload ，返回完整 URL
    :param full_params:
    :param payload:
    :param ori_value:
    :return:
    """
    params = full_params.split('=')[0]
    if not ori_value:
        query = params + '=' + str(payload)
    else:
        query = params + '=' + str(ori_value) + str(payload)

    url = re.sub(full_params, query, conf.TARGET['url'])
    return url


def parse_file_paths(page):
    """
    在网站页面中查找可能出现的绝对路径
    :param page:
    :return:
    """
    pattern = (r"<b>(?P<result>[^<>]+?)</b> on line \d+",
               r"\bin (?P<result>[^<>'\"]+?)['\"]? on line \d+",
               r"(?:[>(\[\s])(?P<result>[A-Za-z]:[\\/][\w. \\/-]*)",
               r"(?:[>(\[\s])(?P<result>/\w[/\w.~-]+)",
               r"\bhref=['\"]file://(?P<result>/[^'\"]+)",
               r"\bin <b>(?P<result>[^<]+): line \d+")

    if page:
        for regex in pattern:
            for match in re.finditer(regex, page):
                abs_file_path = match.group("result").strip()
                page = page.replace(abs_file_path, "")
                if re.search(r"\A[\w]:", abs_file_path) is not None:
                    abs_file_path = abs_file_path.replace('/', '\\') if abs_file_path else abs_file_path
                    logger.info('发现目标网站绝对路径 %s' % abs_file_path)


def payload_handler(i, unpack_payloads, boundries=None):

    params, original_value = i.split('=')

    randnum1 = str(random_int())
    randnum2 = str(random_int())
    randnum3 = str(random_int())
    randstr = random_str()
    randstr2 = random_str()

    def replace_value(value):

        if value is not None:
            value = value.replace("[RANDNUM]", randnum1).replace("[RANDNUM1]", randnum2).replace("[RANDNUM2]", randnum3)
            value = value.replace("[RANDSTR]", randstr).replace("[ORIGINAL]", original_value).replace("[ORIGVALUE]", original_value)
            value = value.replace("[GENERIC_SQL_COMMENT]", "-- [RANDSTR]").replace("[RANDSTR]", randstr2)
        return value

    pack_payloads = replace_value(unpack_payloads['payload'])
    comment = replace_value(unpack_payloads['comment']) if 'comment' in unpack_payloads.keys() else None
    compare = replace_value(unpack_payloads['compare'])
    original_value = '' if not original_value else original_value
    comment = '' if not comment else comment

    if boundries:
        prefix = replace_value(boundries['prefix'])
        suffix = replace_value(boundries['suffix'])

        prefix = '' if not prefix else prefix
        suffix = '' if not suffix else suffix

        # where 为 1 时，payload 添加在原始值后面
        if unpack_payloads['where'] == 1:
            target_url = original_value + prefix + ' ' + pack_payloads + ' ' + suffix
            compare_url = original_value + prefix + ' ' + compare + ' ' + suffix
        # where 为 2 时，原始值替换为整数，再添加 payload
        elif unpack_payloads['where'] == 2:
            target_url = '-' + str(random_int()) + prefix + ' ' + pack_payloads + ' ' + suffix
            compare_url = '-' + str(random_int()) + prefix + ' ' + compare + ' ' + suffix
        # where 为 3 时，直接替换为 payload
        else:
            target_url = prefix + ' ' + pack_payloads + ' ' + suffix
            compare_url = prefix + ' ' + compare + ' ' + suffix
        return target_url, compare_url
    else:
        # where 为 1 时，payload 添加在原始值后面
        if unpack_payloads['where'] == 1:
            target_url = original_value + ' ' + pack_payloads + ' ' + comment
            compare_url = original_value + ' ' + compare + ' ' + comment
        # where 为 2 时，原始值替换为整数，再添加 payload
        elif unpack_payloads['where'] == 2:
            target_url = '-' + str(random_int()) + ' ' + pack_payloads + ' ' + comment
            compare_url = '-' + str(random_int()) + ' ' + compare + ' ' + comment
        # where 为 3 时，直接替换为 payload
        else:
            target_url = ' ' + pack_payloads + ' ' + comment
            compare_url = ' ' + compare + ' ' + comment
        return target_url, compare_url
