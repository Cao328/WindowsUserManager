from flask import Flask, request, jsonify, render_template, session
import logging
from logging.handlers import RotatingFileHandler
import win32net
import win32netcon
import win32security
import pywintypes
import os
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
#app.secret_key = os.environ.get('SECRET_KEY')
app.secret_key = 'User@WIN11'
CORS(app)

SERVER = None
LOG_FILE = os.path.join(os.path.dirname(__file__), 'app.log')

if not os.path.exists(os.path.dirname(LOG_FILE)):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

handler = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s'))
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)
app.logger.propagate = False
app.logger.info('日志初始化完成，写入日志文件: %s', LOG_FILE)

@app.before_request
def log_request():
    app.logger.info(
        'Request: method=%s path=%s user=%s ip=%s',
        request.method,
        request.path,
        session.get('username', 'anonymous'),
        request.remote_addr,
    )


def is_admin_user(username):
    """判断是否为管理员用户"""
    try:
        groups = win32net.NetUserGetLocalGroups(SERVER, username)
        admin_groups = ['Administrators', 'Domain Admins', '管理员', '域管理员']
        for group in groups:
            if any(g.lower() in group.lower() for g in admin_groups):
                return True
        return False
    except:
        return False


def validate_windows_user(username, password):
    """验证Windows用户凭据"""
    app.logger.info('Validate Windows credentials: username=%s', username)
    try:
        handle = win32security.LogonUser(
            username,
            SERVER if SERVER else '.',
            password,
            win32security.LOGON32_LOGON_INTERACTIVE,
            win32security.LOGON32_PROVIDER_DEFAULT
        )
        handle.close()
        app.logger.info('Validate Windows credentials succeeded: username=%s', username)
        return True
    except pywintypes.error:
        app.logger.warning('Validate Windows credentials failed: username=%s', username)
        return False
    except Exception as e:
        app.logger.exception('Validate Windows credentials error: username=%s', username)
        return False


def get_user_info(username):
    """获取用户详细信息"""
    app.logger.info('Get user info: username=%s', username)
    try:
        info = win32net.NetUserGetInfo(SERVER, username, 3)
        result = {
            'name': info['name'],
            'full_name': info.get('full_name', ''),
            'comment': info.get('comment', ''),
            'locked': bool(info['flags'] & win32netcon.UF_LOCKOUT),
            'disabled': bool(info['flags'] & win32netcon.UF_ACCOUNTDISABLE),
            'is_admin': is_admin_user(username)
        }
        app.logger.info('Get user info success: username=%s is_admin=%s', username, result['is_admin'])
        return result
    except Exception as e:
        app.logger.exception('Get user info failed: username=%s', username)
        return None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    app.logger.info('Login attempt: username=%s', username)
    
    if not username or not password:
        app.logger.warning('Login failed: missing username or password')
        return jsonify({'success': False, 'message': '用户名和密码不能为空'}), 400
    
    if not validate_windows_user(username, password):
        app.logger.warning('Login failed: invalid credentials for %s', username)
        return jsonify({'success': False, 'message': '用户名或密码错误'}), 401
    
    user_info = get_user_info(username)
    if not user_info:
        app.logger.error('Login failed: 无法获取用户信息 username=%s', username)
        return jsonify({'success': False, 'message': '无法获取用户信息'}), 500
    
    session['username'] = username
    session['is_admin'] = user_info['is_admin']
    app.logger.info('Login success: username=%s is_admin=%s', username, user_info['is_admin'])
    
    return jsonify({
        'success': True,
        'data': {
            'username': username,
            'full_name': user_info['full_name'],
            'is_admin': user_info['is_admin']
        }
    })


@app.route('/api/logout', methods=['POST'])
def logout():
    app.logger.info('Logout: username=%s', session.get('username', 'unknown'))
    session.clear()
    return jsonify({'success': True, 'message': '已退出登录'})


@app.route('/api/current-user', methods=['GET'])
def get_current_user():
    if 'username' not in session:
        return jsonify({'success': False, 'message': '未登录'}), 401
    app.logger.info('Get current user: username=%s', session['username'])
    return jsonify({
        'success': True,
        'data': {
            'username': session['username'],
            'is_admin': session.get('is_admin', False)
        }
    })


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'success': False, 'message': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'success': False, 'message': '请先登录'}), 401
        if not session.get('is_admin'):
            return jsonify({'success': False, 'message': '权限不足'}), 403
        return f(*args, **kwargs)
    return decorated


@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    if not session.get('is_admin'):
        return jsonify({'success': False, 'message': '权限不足'}), 403
    admin = session['username']
    app.logger.info('List users request by admin=%s', admin)
    
    try:
        users = []
        resume = 0
        while True:
            entries, total, resume = win32net.NetUserEnum(
                SERVER, 1, win32netcon.FILTER_NORMAL_ACCOUNT, resume
            )
            for u in entries:
                users.append({
                    'name': u['name'],
                    'full_name': u.get('full_name', ''),
                    'comment': u.get('comment', ''),
                    'locked': bool(u['flags'] & win32netcon.UF_LOCKOUT),
                    'disabled': bool(u['flags'] & win32netcon.UF_ACCOUNTDISABLE),
                })
            if resume == 0:
                break
        app.logger.info('List users success: admin=%s count=%d', admin, len(users))
        return jsonify({'success': True, 'data': users})
    except Exception as e:
        app.logger.exception('List users failed: admin=%s', admin)
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/users/<username>', methods=['GET'])
@login_required
def get_user(username):
    caller = session.get('username')
    app.logger.info('Get user request: caller=%s target=%s', caller, username)
    # Allow admin or the user themself
    if not session.get('is_admin') and username != caller:
        app.logger.warning('Get user forbidden: caller=%s target=%s', caller, username)
        return jsonify({'success': False, 'message': '权限不足'}), 403
    info = get_user_info(username)
    if not info:
        app.logger.error('Get user failed: cannot fetch info username=%s', username)
        return jsonify({'success': False, 'message': '无法获取用户信息'}), 404
    app.logger.info('Get user success: caller=%s target=%s', caller, username)
    return jsonify({'success': True, 'data': info})


@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.json
    username = data.get('username') if data else None
    password = data.get('password') if data else None
    admin = session.get('username', 'unknown')
    app.logger.info('Create user attempt: admin=%s username=%s', admin, username)
    if not username or not password:
        app.logger.warning('Create user failed: missing username or password admin=%s', admin)
        return jsonify({'success': False, 'message': '用户名和密码不能为空'}), 400
    try:
        user_info = {
            'name': username,
            'password': password,
            'priv': win32netcon.USER_PRIV_USER,
            'home_dir': None,
            'comment': data.get('comment', '') if data else '',
            'flags': win32netcon.UF_NORMAL_ACCOUNT | win32netcon.UF_DONT_EXPIRE_PASSWD,
            'script_path': None,
            'password_age': 0,
        }
        app.logger.info('Calling NetUserAdd: %s', {k: v for k, v in user_info.items() if k != 'password'})
        win32net.NetUserAdd(SERVER, 1, user_info)
        app.logger.info('Create user success: admin=%s username=%s', admin, username)
        return jsonify({'success': True, 'message': f"用户 {username} 创建成功"})
    except pywintypes.error as e:
        app.logger.exception('Create user pywintypes.error: admin=%s username=%s', admin, username)
        return jsonify({'success': False, 'message': str(e.args)}), 400
    except Exception as e:
        app.logger.exception('Create user exception: admin=%s username=%s', admin, username)
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/password', methods=['PUT'])
@login_required
def change_password():
    data = request.json
    current_user = session['username']
    is_admin = session.get('is_admin', False)
    target_user = data.get('username', current_user)

    if not is_admin and target_user != current_user:
        return jsonify({'success': False, 'message': '普通用户只能修改自己的密码'}), 403
    
    new_password = data.get('password') if data else None
    if not new_password:
        return jsonify({'success': False, 'message': '新密码不能为空'}), 400

    try:
        app.logger.info("NetUser password change called: SERVER=%s target_user=%s is_admin=%s", SERVER, target_user, is_admin)
        app.logger.info("New password length=%d", len(new_password))
        if is_admin:
            level = 1003
            payload = {'password': new_password}
            app.logger.info("Calling NetUserSetInfo level %s payload=%s", level, payload)
            win32net.NetUserSetInfo(None, target_user, level, payload)
        else:
            old_password = data.get('old_password') if data else None
            if not old_password:
                return jsonify({'success': False, 'message': '普通用户修改密码需提供当前密码 (old_password)'}), 400
            app.logger.info("Calling NetUserChangePassword SERVER=%s user=%s", SERVER, target_user)
            win32net.NetUserChangePassword(None, target_user, old_password, new_password)
        return jsonify({'success': True, 'message': f"用户 {target_user} 密码已修改"})
    except pywintypes.error as e:
        app.logger.exception("pywintypes.error when changing password")
        return jsonify({'success': False, 'message': str(e.args)}), 400
    except Exception as e:
        app.logger.exception("Exception when changing password")
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/users/<username>/unlock', methods=['POST'])
@admin_required
def unlock_user(username):
    admin = session.get('username', 'unknown')
    app.logger.info('Unlock user attempt: admin=%s username=%s', admin, username)
    try:
        user_info = win32net.NetUserGetInfo(SERVER, username, 3)
        user_info['flags'] = user_info['flags'] & ~win32netcon.UF_LOCKOUT
        win32net.NetUserSetInfo(SERVER, username, 3, user_info)
        app.logger.info('Unlock user success: admin=%s username=%s', admin, username)
        return jsonify({'success': True, 'message': f"用户 {username} 已解锁"})
    except Exception as e:
        app.logger.exception('Unlock user failed: admin=%s username=%s', admin, username)
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/users/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    admin = session.get('username', 'unknown')
    app.logger.info('Delete user attempt: admin=%s username=%s', admin, username)
    if username == session['username']:
        app.logger.warning('Delete user blocked: admin tried to delete current session user admin=%s username=%s', admin, username)
        return jsonify({'success': False, 'message': '不能删除当前登录用户'}), 400
    
    try:
        win32net.NetUserDel(SERVER, username)
        app.logger.info('Delete user success: admin=%s username=%s', admin, username)
        return jsonify({'success': True, 'message': f"用户 {username} 已删除"})
    except Exception as e:
        app.logger.exception('Delete user failed: admin=%s username=%s', admin, username)
        return jsonify({'success': False, 'message': str(e)}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)