import os
import pprint
import json
import requests
from tempfile import mkdtemp
from flask import Flask, jsonify, request, render_template, url_for, redirect, session
from flask_caching import Cache
from werkzeug.exceptions import Forbidden
from pylti1p3.contrib.flask import FlaskOIDCLogin, FlaskMessageLaunch, FlaskRequest, FlaskCacheDataStorage
from pylti1p3.tool_config import ToolConfJsonFile
from pylti1p3.registration import Registration


PAGE_TITLE = 'Canvas LTI Framework with API Integration'
API_BASE = 'https://biztechcollege.instructure.com'
CLIENT_ID_API = 187330000000000104
CLIENT_SECRET_API = 'AViMOf4K4cOXT2yLcchw6Wzg6sxYfM8sTgDf1WzKTQrvnrhisTyCkxcAGIT0dMaa'#18733~NH2yqQUAicdAUdUM2UsVECjW6RorTc0StQi82uL8YdSiCjkg9RTWcphF9UsIwEVM
REDIRECT_URI_API = 'https://jasonhemu-fictional-engine-x5pg7q6vp4fpj5r-9001.preview.app.github.dev/oauth/'
OAUTH_URL = '{}/login/oauth2/auth?client_id={}&response_type=code&redirect_uri={}&state=BIZTECH'.format(
    API_BASE,
    CLIENT_ID_API,
    REDIRECT_URI_API
)

class ReverseProxied:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        scheme = environ.get('HTTP_X_FORWARDED_PROTO')
        if scheme:
            environ['wsgi.url_scheme'] = scheme
        return self.app(environ, start_response)


app = Flask('canvas_lti_framework', template_folder='templates', static_folder='static')
app.wsgi_app = ReverseProxied(app.wsgi_app)

config = {
    "DEBUG": True,
    "ENV": "development",
    "CACHE_TYPE": "simple",
    "CACHE_DEFAULT_TIMEOUT": 600,
    "SECRET_KEY": "replace-me",
    "SESSION_TYPE": "filesystem",
    "SESSION_FILE_DIR": mkdtemp(),
    "SESSION_COOKIE_NAME": "flask-app-sessionid",
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SECURE": False,   # should be True in case of HTTPS usage (production)
    "SESSION_COOKIE_SAMESITE": None,  # should be 'None' in case of HTTPS usage (production)
    "DEBUG_TB_INTERCEPT_REDIRECTS": False
}

app.config.from_mapping(config)
cache = Cache(app)

class ExtendedFlaskMessageLaunch(FlaskMessageLaunch):
    def validate_nonce(self):
        iss = self.get_iss()
        deep_link_launch = self.is_deep_link_launch()
        if iss == "http://imsglobal.org" and deep_link_launch:
            return self
        return super().validate_nonce()

def get_lti_config_path():
    return os.path.join(app.root_path, '..', 'configs', 'configs.json')

def get_launch_data_storage():
    return FlaskCacheDataStorage(cache)

def get_jwk_from_public_key(key_name):
    key_path = os.path.join(app.root_path, '..', 'configs', key_name)
    f = open(key_path, 'r')
    key_content = f.read()
    jwk = Registration.get_jwk(key_content)
    f.close()
    return jwk

def get_api_token_authorization(code):
    api = '{}/login/oauth2/token'.format(API_BASE)
    params = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID_API,
        'client_secret': CLIENT_SECRET_API,
        'redirect_uri': REDIRECT_URI_API,
        'code': code
    }
    r = requests.post(api, params=params).json()
    return r

def get_site_student_enrollment_count(canvas_site_id, access_token):
    api = '{}/api/v1/courses/{}'.format(API_BASE, canvas_site_id)
    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    params = {
        'include[]': 'total_students'
    }
    r = requests.get(api, params=params, headers=headers).json()
    return r


@app.route('/login/', methods=['GET', 'POST'])
def login():
    tool_conf = ToolConfJsonFile(get_lti_config_path())
    launch_data_storage = get_launch_data_storage()
    flask_request = FlaskRequest()
    target_link_uri = flask_request.get_param('target_link_uri')
    if not target_link_uri:
        raise Exception('Missing "target_link_uri" param')

    oidc_login = FlaskOIDCLogin(
        flask_request, 
        tool_conf, 
        launch_data_storage=launch_data_storage
    )

    return oidc_login.enable_check_cookies().redirect(target_link_uri)

@app.route('/launch/', methods=['POST'])
def launch():
    tool_conf = ToolConfJsonFile(get_lti_config_path())
    launch_data_storage = get_launch_data_storage()
    flask_request = FlaskRequest()
    message_launch = ExtendedFlaskMessageLaunch(
        flask_request, 
        tool_conf, 
        launch_data_storage=launch_data_storage
    )
    message_launch_data = message_launch.get_launch_data()
    cache.set("launch_id", message_launch.get_launch_id())
    course_id = message_launch_data.get(
        'https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice', {}
    ).get('context_memberships_url', None).split("/")[-2]

    params = {
        'launch_data': message_launch.get_launch_data(),
        'launch_id': message_launch.get_launch_id(),
        'user_name': message_launch_data.get('name', ''),
        'user_email': message_launch_data.get('email', ''),
        'user_sis_id': message_launch_data.get('https://purl.imsglobal.org/spec/lti/claim/lis', {}).get('person_sourcedid', None),
        'course_title': message_launch_data.get('https://purl.imsglobal.org/spec/lti/claim/context',{}).get('title', None),
        'course_id': course_id,
        'course_sis_id': message_launch_data.get('https://purl.imsglobal.org/spec/lti/claim/lis', {}).get('course_offering_sourcedid', None),
        'course_roles': message_launch_data.get('https://purl.imsglobal.org/spec/lti/claim/roles', None)
    }
    return render_template('launch.html', **params)

@app.route('/dance/', methods=['GET']) #########
def dance():
    return redirect(OAUTH_URL)
    

@app.route('/oauth/', methods=['GET', 'POST'])
def oauth():
    tool_conf = ToolConfJsonFile(get_lti_config_path())
    flask_request = FlaskRequest()
    launch_data_storage = get_launch_data_storage()
    message_launch = ExtendedFlaskMessageLaunch.from_cache(
        cache.get('launch_id'), 
        flask_request, tool_conf,
        launch_data_storage=launch_data_storage
    )
    message_launch_data = message_launch.get_launch_data()
    course_id = message_launch_data.get(
        'https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice', {}
    ).get('context_memberships_url', None).split("/")[-2]
    code = request.args.get('code')
    if code:
        r = get_api_token_authorization(code)
        total_students = get_site_student_enrollment_count(course_id, r['access_token'])
    params = {
        'code': code,
        'access_token': r['access_token'],
        'refresh_token': r['refresh_token'],
        #'launch_data': message_launch.get_launch_data(),
        #'launch_id': message_launch.get_launch_id(),
        'user_name': message_launch_data.get('name', ''),
        'user_email': message_launch_data.get('email', ''),
        'user_id': r['user']['id'],
        'user_sis_id': message_launch_data.get('https://purl.imsglobal.org/spec/lti/claim/lis', {}).get('person_sourcedid', None),
        'course_title': message_launch_data.get('https://purl.imsglobal.org/spec/lti/claim/context',{}).get('title', None),
        'course_id': course_id,
        'course_sis_id': message_launch_data.get('https://purl.imsglobal.org/spec/lti/claim/lis', {}).get('course_offering_sourcedid', None),
        'course_roles': message_launch_data.get('https://purl.imsglobal.org/spec/lti/claim/roles', None),
        'course_total_students': total_students['total_students'],

    }

    return render_template('index.html', **params)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9001)