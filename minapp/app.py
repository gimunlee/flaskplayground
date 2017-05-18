"""The entry of flask app"""
from flask import Flask
from flask import url_for, request
from flask import render_template
from flask import redirect, flash, abort
from flask import make_response
from flask  import escape, session
from time import time

from werkzeug.utils import secure_filename

import os

APP = Flask(__name__)
APP.secret_key = "asdklfnci;ovz"

@APP.route('/')#, methods=['GET','POST'])
def index():
    """Index page"""
    if session.get('username') != None :
        name = session['username']
    else :
        name = 'Flask Beginner'
    resp = make_response(
        render_template(
            'index.html',
            msg="Hello"
        )
    )
    # if request.method == 'POST':
        # resp = make_response(render_template(
        #     'test.html',
        #     name=name,
        #     method='POST',
        #     door=url_for('static', filename='door'),
        #     parameters=request.args.get('detail'),
        #     passwd=request.form['passwd'],
        #     stamp=request.cookies.get('stamp')))
    # else:
        # resp = make_response(render_template(
        #     'test.html',
        #     name=name,
        #     method='GET',
        #     door=url_for('static', filename='door'),
        #     parameters=request.args.get('detail'),
        #     stamp=request.cookies.get('stamp')))
    return resp
@APP.route('/profile')
def profile():
    if session.get('username') != None :
        resp = make_response('The user %s' % escape(session['username']))
    else:
        resp = make_response('Not logged in')
    return resp
@APP.route('/login', methods=['GET', 'POST'])
def login():
    """login with username form"""
    if request.method == 'POST':
        if 'username' in request.form:
            session['username'] = request.form.get('username')
            return redirect(url_for('index'))
        else:
            return 'no username'
    else:
        return make_response('''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=submit value=Login>
        </form>
        ''')
@APP.route('/logout')
def logout():
    """remove the username from the session"""
    session.pop('username', None)
    return redirect(url_for('index'))
@APP.route('/door', methods=['POST'])
def put_door_img():
    """Update door img"""

    upload_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/door')
    allowed_extensions = set(['jpg', 'jpeg', 'png', 'gif'])

    if 'file' not in request.files:
        flash('No file')
    else:
        file_ = request.files['file']
        if not file_ or file_.filename == '':
            flash('No selected file')
        elif file_ and '.' in file_.filename and file_.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
            file_.save(upload_path)
            flash('File uploaded')
        else:
            flash('File not allowed')
    return redirect(url_for('index'))

@APP.route('/post/<int:post_id>')
def get_post(post_id):
    """Returns the post id back"""
    return make_response('The id of the post is %d' % post_id)
@APP.route('/post/')
def get_posts_all():
    """Returns all posts"""
    return make_response('all posts')

@APP.route('/user/<username>')
def show_user_profile(username):
    """Show the user's profile"""
    return make_response(username)

#javascript:alert(document.cookie)
STAMPS = []
@APP.route('/stamp')
def set_stamp():
    """get and set stamp"""
    stamp = time()
    STAMPS.append(stamp)
    print 'stamp is %s' % stamp
    print STAMPS

    resp = make_response('t')
    resp.set_cookie('stamp', str(stamp))
    return resp

@APP.route('/treasure')
def get_treasure():
    """treasure page, redirecting to the police"""
    return redirect(url_for('go_police'))

@APP.route('/police')
def go_police():
    """police station"""
    abort(401)

@APP.errorhandler(401)
def page_access_denied(error):
    return make_response('Acces denied from police')

with APP.test_request_context('/user', method='GET'):
    print url_for('get_post', post_id=3)
    print url_for('index',msg=3)

APP.secret_key = 'LeeSuperSuperSecretKey'