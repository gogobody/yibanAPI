###易班 FLASK-API ###

基于flask python2 or python
tip : 使用错误处理程序
    from website.helpers.error_handlers import CustomFlaskErr
    在路由中注册
    @app.errorhandler(CustomFlaskErr)
    def handle_flask_error(error):
        # response 的 json 内容为自定义错误代码和错误信息
        response = json.dumps(error.to_dict())
        return response
    使用：
        @app.route('/')
        def index():
            raise CustomFlaskErr(return_code=40000) #return_code 状态码在error_handlers中定义，可将所有状态码集中管理
        response:
        {
            status_code: 400,
            message: "TOKEN_NOT_FOOUND",
            return_code: 40000
        }

##API 使用
1.在路由中添加易班授权认证url  ：
    eg：
    from website.YibanApi.Client import YiBanApi
    @app.route('/oauth')
    def do_oauth():
        YiBanApi.do_oauth()
2.使用:
    eg:
    {"base_info":YiBanApi.base_info(),"detail_info":YiBanApi.detail_info()}
    response:
    {
        data: {
            base_info: {
                access_token: "a9a7f7f6aac4e68a9855346c7d960255198a419b",
                userid: "5559093",
                username: "路人甲",
                usernick: "路人甲",
                usersex: "M",
                visit_time: 1502114001
            },
            detail_info: {
                yb_exp: "5931",
                yb_money: "351031",
                yb_regtime: "2015-07-23 11:43:18",
                yb_schoolid: "527",
                yb_schoolname: "重庆大学",
                yb_sex: "M",
                yb_userhead: "http://img02.fs.yiban.cn/5559093/avatar/user/200",
                yb_userid: "5559093",
                yb_username: "路人甲",
                yb_usernick: "路人甲"
            }
            },
        status: true
        }