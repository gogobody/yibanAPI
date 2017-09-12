#!/usr/bin/env python
# coding=utf-8
import json
import time
import urllib,requests
from functools import wraps
from flask import current_app, request, session, redirect
from .error_handlers import *
from Crypto.Cipher import AES
from .user_api.user_api import user_real_info
from .msg.send_letter import send_letter

def Schooljurisdiction_required(f):
    # @wraps(f)
    def decorated_function(*args,**kwargs):
        res = json.loads(urllib.request.urlopen(url='https://openapi.yiban.cn/user/real_me?access_token=%s' % YiBanApi.get_token()).read())
        if res["status"] == "error" and res["info"]["code"] == 'e007':
            raise CustomFlaskErr(return_code=insufficient_privilege)
        if current_app.debug:
            return f(*args, **kwargs)
        else:
            try:
                return f(*args, **kwargs)
            except Exception as e:
                current_app.logger.error('视图出错，%s' % str(e))
                raise CustomFlaskErr(return_code=UNKNOW_ERROR,payload={"视图出错":"未知错误"})
    return decorated_function

class YiBanApi:
    # app_id = current_app.config.get('APPID')
    # app_secret = current_app.config.get('APP_SECRET')
    # verify_request = None
    apiURL = "https://openapi.yiban.cn"
    def __init__(self):
        self.app_id = current_app.config.get('APPID')
        self.app_secret = current_app.config.get('APP_SECRET')
        self.verify_request = None

    @classmethod
    def do_oauth(cls):
        auth_url = 'https://openapi.yiban.cn/oauth/authorize?client_id=%s&redirect_uri=%s&display=mobile' % (
            current_app.config.get('APPID'), current_app.config.get('YIBAN_CALLBACK'))

        if 'verify_request' not in request.args:
            return redirect(auth_url)
        verify_request = request.args.get('verify_request')

        session['verify_request'] = verify_request

        base_info = cls.base_info()
        # print(base_info)
        if not base_info:
            raise CustomFlaskErr(return_code=OAUTH_ERROR)
        session['yb_userid'] = base_info['userid']
        session['token'] = base_info['access_token']
        if cls.is_visit_expire():
            raise CustomFlaskErr(return_code=OAUTH_OUT_OF_DATE)

        detail_info = cls.detail_info()
        if not detail_info:
            raise CustomFlaskErr(return_code=OAUTH_ERROR)



    @classmethod
    def base_info(cls,verify_request = None):
        """
                    获取易班授权的基本信息
                    :return: {
                        'access_token': 见易班开发文档,
                        'username': 易班用户名,
                        'usernick': 易班用户名,
                        'usersex': 易班用户性别,
                        'userid': 易班用户ID,
                        'visit_time': 授权时间
                     }
                     or False
                    """
        if not verify_request:
            try:
                verify_request = session['verify_request']
            except Exception as e:
                print(e)
                return False
        user_info = cls.decrypt(verify_request)
        # print(user_info)
        if user_info:
            try:
                _base_info = {
                    'access_token': user_info['visit_oauth']['access_token'],
                    'username': user_info['visit_user']['username'],
                    'usernick': user_info['visit_user']['usernick'],
                    'usersex': user_info['visit_user']['usersex'],
                    'userid': user_info['visit_user']['userid'],
                    'visit_time': user_info['visit_time']
                }
                return _base_info
            except Exception as e:
                print(e)
                return False
        return False

    @classmethod
    def detail_info(cls):
        """
        :return:
        {
        "yb_money": "351010",
        "yb_usernick": "\u8def\u4eba\u7532",
        "yb_schoolname": "\u91cd\u5e86\u5927\u5b66",
        "yb_regtime": "2015-07-23 11:43:18",
        "yb_userhead": "http://img02.fs.yiban.cn/5559093/avatar/user/200",
        "yb_userid": "5559093",
        "yb_schoolid": "527",
        "yb_sex": "M",
        "yb_username": "\u8def\u4eba\u7532",
        "yb_exp": "5925"
}

        or False
        """
        token = session.get('token')
        if not token:
            raise CustomFlaskErr(return_code=TOKEN_NOT_FOOUND)

        res = urllib.request.urlopen(url='https://openapi.yiban.cn/user/me?access_token=%s' % token).read()
        res = json.loads(res)
        print("res:",res)
        if res and res['status'] == 'success':
            return res['info']
        else:
            # self.error_msg = res['info']['msgCN']
            return False

    @classmethod
    def decrypt(cls,verify_request):
        """
        {
            "visit_oauth": {
                "access_token": "5a5595d4869d5afca35fefe89fb4a3d14f085be1",
                "token_expires": 1489940242
            },
            "visit_time": 1488642455,
            "visit_user": {
                "username": "0x5f3759df",
                "usernick": "0x5f3759df",
                "usersex": "M",
                "userid": "5566213"
            }
        }
        """
        try:
            mode = AES.MODE_CBC
            data = YiBanApi.h2b(verify_request)
            # print(data)
            decryptor = AES.new(current_app.config.get('APP_SECRET'), mode, IV=current_app.config.get('APPID'))
            plain = decryptor.decrypt(data)
            # plain = "".join([plain.strip().rsplit("}", 1)[0], "}"])
            print(plain)
            # print(plain.decode())
            print((plain.rstrip(chr(0).encode('ascii'))))
            print("bbbb")

            oauth_state = json.loads(plain.rstrip(chr(0)))

            # print oauth_state
            return oauth_state
        except Exception as e:
            print(e)
            return False

    @classmethod
    def is_visit_expire(cls, max_seconds=600):
        if not cls.base_info():
            return False
        return int(time.time()) - cls.base_info().get('visit_time', 0) > max_seconds

    @staticmethod
    def h2b(s):
        import array, string
        ar = []

        start = 0
        if s[:2] == '0x':
            start = 2

        for i in range(start, len(s), 2):
            try:
                num = string.atoi("%s" % (s[i:i + 2],), 16)
            except Exception as e:
                num =int((s[i:i + 2]),16)
                print(s[i:i + 2], "  ",chr(num))
            ar.append(chr(num))
        # print(ar.tounicode())
        print(ar)
        return ''.join(ar)

    @staticmethod
    def get_token():
        try:
            return session['token']
        except KeyError:
            raise CustomFlaskErr(return_code=TOKEN_NOT_FOOUND)

    @classmethod
    def get_real_user_info(cls):
        '''
        :return:
         {
        "status":"success",
        "info":{
            yb_userid: "5559093",
            yb_username: "路人甲",
            yb_usernick: "路人甲",
            yb_sex: "M",
            yb_money: "351076",
            yb_exp: "5964",
            yb_userhead: "http://img02.fs.yiban.cn/5559093/avatar/user/200",
            yb_schoolid: "527",
            yb_schoolname: "重庆大学",
            yb_regtime: "2015-07-23 11:43:18",
            yb_realname: "王纬略",
            yb_birthday: "1995-01-28",
            yb_studentid: "20154236",
            yb_identity: "学生"
        }
    }
        '''
        @Schooljurisdiction_required
        def a():
            return user_real_info(cls.apiURL,cls.get_token())
        return a()

    @classmethod
    def send_letter(cls,to_yb_uid,msg):
        data = {
            "to_yb_uid" : to_yb_uid,
            "content" : msg,
            "access_token" : cls.get_token()
        }
        return send_letter(cls.apiURL,data)