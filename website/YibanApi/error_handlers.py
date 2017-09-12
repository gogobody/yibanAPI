#!/usr/bin/env python
# coding=utf-8
from flask import current_app

TOKEN_NOT_FOOUND = 40000
MAP_SEARCH_ERROR = 40001
insufficient_privilege = 40002
OAUTH_ERROR = 40003
OAUTH_OUT_OF_DATE = 40004

UNKNOW_ERROR = 50000
J_MSG = {
    TOKEN_NOT_FOOUND:"TOKEN_NOT_FOOUND",
    MAP_SEARCH_ERROR:"MAP_SEARCH_ERROR",
    UNKNOW_ERROR:"UNKNOW_ERROR",
    insufficient_privilege:"权限不够",
    OAUTH_ERROR :"oAuth授权错误!!",
    OAUTH_OUT_OF_DATE:"授权已过期，请重新授权"
}
class CustomFlaskErr(Exception):

    # 默认的返回码
    status_code = 400
    return_code = UNKNOW_ERROR
    # 自己定义了一个 return_code，作为更细颗粒度的错误代码
    def __init__(self, return_code=None, status_code=None, payload=None):
        Exception.__init__(self)
        self.return_code = return_code
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    # 构造要返回的错误代码和错误信息的 dict
    def to_dict(self):
        rv = dict(self.payload or ())

        # 增加 dict key: return code
        rv['return_code'] = self.return_code

        # 增加 dict key: message, 具体内容由常量定义文件中通过 return_code 转化而来
        print(self.return_code)
        rv['message'] = J_MSG[self.return_code]
        rv['status_code'] = self.status_code
        # 日志打印
        current_app.logger.warning(J_MSG[self.return_code])

        return rv

