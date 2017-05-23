"""SImple hello world flask app"""
import sys
from os import path, chdir, getpid

from datetime import datetime
from urlparse import urlparse, urljoin
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user # pylint: disable=import-error, line-too-long
from werkzeug.security import generate_password_hash, check_password_hash

sys.stdout = sys.stderr
chdir(path.abspath(path.dirname(__file__)))

def is_safe_redirect_url(target):
    """Validate the url"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
            ref_url.netloc == test_url.netloc

def render_template_with_pid(template, **args):
    """Add pid after the original arguments"""
    args['pid'] = getpid()
    return render_template(template, **args)

class WeatherUser(UserMixin):
    """Custom User class"""
    def temp(self):
        """temp function"""
        print 'temp : ' + self.get_id()
    def __init__(self, userid, name):
        self.id = userid # pylint: disable=invalid-name
        self.name = name

    @classmethod
    def get(cls, user_id):
        """Find the user with his id"""
        with connect_db() as conn:
            cursor = conn.execute("""
            SELECT userid, username
              FROM users
             WHERE userid = ?
             """, (user_id,))
            result = cursor.fetchone()
            if result:
                return WeatherUser(*result)
        return None

_MILLION = 1000000

app = Flask(__name__) # pylint: disable=invalid-name

def debug_flash(msg):
    """Flash a message with the timestamp for debug"""
    if app.debug:
        flash(str(datetime.now()) + ": " + msg)

app.config.from_pyfile('./settings.py')
app.secret_key = "asdklfnci;ovz"
if app.debug:
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 1
    print 'debug mode'

login_manager = LoginManager() # pylint: disable=invalid-name
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    """Loader for login manager"""
    # debug_flash('loaded')
    return WeatherUser.get(user_id)
login_manager.login_view = 'login'
login_manager.login_message = ''

def connect_db():
    """Connect to the db enlisted in the config"""
    return sqlite3.connect(app.config['DATABASE'])

def query_full_info(limit, offset):
    """Query rows of size having all columns except reg_date after the offset"""
    result = None
    with connect_db() as conn:
        cursor = conn.execute("""
           SELECT basicdate, local_name, precipitation, avg_snow, min_temperature, max_temperature, avg_temperature
             FROM tbl_weather
       INNER JOIN tbl_local_info
               ON tbl_weather.local_code = tbl_local_info.local_code
         ORDER BY basicdate
            LIMIT ?
           OFFSET ?
        """, (limit, offset))
        result = cursor.fetchall()
    return result
def query_count():
    """Query the number of records"""
    result = None
    with connect_db() as conn:
        cursor = conn.execute("""
        SELECT COUNT(*)
          FROM tbl_weather;
        """)
        result = cursor.fetchone()
        if result:
            result = result[0]
    return result
@app.route('/hash')
def hash_():
    """temporary hashing page"""
    plain = request.args.get('plain')
    if plain:
        return generate_password_hash(plain)
    return 'No plain text given'

@app.route('/')
def index():
    """Index page"""
    page_size = int(request.args.get('pagesize') or 10)
    page_current_index = int(request.args.get('pageindex') or 0)

    count = query_count()
    page_count = count // int(page_size)

    #condisering the case around 0
    page_lowerbound_index = max(page_current_index - 2, 0)

    #considering the case around max
    if page_current_index + 2 > page_count + 1:
        page_upperbound_index = min(page_current_index + 2, page_count + 1)
        page_lowerbound_index = page_upperbound_index - 4
    else:
        page_upperbound_index = page_lowerbound_index + 4

    return render_template_with_pid(
        'index.html',
        pid=getpid(),
        is_logged_in=session.get('is_logged_in'),
        username=session.get('username'),
        count=query_count(),
        page_indexes=range(page_lowerbound_index, page_upperbound_index+1),
        page_current_index=page_current_index,
        weather_table=query_full_info(page_size, page_current_index * page_size),
        page_size=page_size
    )
@app.route('/query')
def query():
    """General query page"""
    limit = request.args.get('limit')
    offset = request.args.get('offset')

    sql_statement = """
    SELECT * FROM tbl_weather
     LIMIT :limit
    OFFSET :offset
    """

    if limit is None:
        limit = 10
    if offset is None:
        offset = 0

    with connect_db() as conn:
        cursor = conn.execute(sql_statement, {"limit": limit, "offset": offset})
        result = cursor.fetchall()
    return str(len(result)) + ' rows quieried.' + str(result)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """login"""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        def validate_form(user_id):
            """The local function to validate the password"""
            print 'current url : ' + request.url
            password = request.form.get('password')

            password_hash = None
            with connect_db() as conn:
                cursor = conn.execute("""
                SELECT passwd_hash
                FROM users
                WHERE userid=?
                """, (str(user_id),))
                result = cursor.fetchone()
            if result:
                password_hash = result[0]
                return check_password_hash(password_hash, password)
            return False
        if validate_form(user_id):
            user = WeatherUser.get(user_id)
        else:
            user = None

        if user is None:
            debug_flash('Given info is wrong')
            return redirect(url_for('index'))

        if login_user(user):
            debug_flash('Logged in as %s successfully.' % str(user.name))

            next_path = request.args.get('next')
            if not is_safe_redirect_url(next_path):
                return abort(400)
            return redirect(next_path or url_for('index'))
        else:
            return render_template_with_pid('login.html')
    else:
        return render_template_with_pid('login.html')
@app.route('/logout')
@login_required
def logout():
    """logout"""
    result = logout_user()
    if result:
        debug_flash('logged out successfully')
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Sign up"""
    if request.method == 'GET':
        return render_template_with_pid('signup.html')
    else:
        redirect_itself = redirect(request.full_path)
        def validate_input():
            """Validate input from the client"""
            user_id = request.form.get('user_id')
            passwd_first = request.form.get('passwd_first')
            passwd_second = request.form.get('passwd_second')
            user_name = request.form.get('user_name')
            debug_flash(user_id)
            debug_flash(passwd_first)
            debug_flash(request.form.get('passwd_second'))

            if (not isinstance(passwd_first, unicode)) or (len(passwd_first) < 1):
                debug_flash('password should be longer than blank')
            elif len(passwd_first) > 30:
                debug_flash('password is too long (<= 30)')
            elif passwd_first != passwd_second:
                debug_flash('two password doesnt match')
            else:
                return {'user_id':user_id,
                        'passwd_hash':generate_password_hash(passwd_first),
                        'user_name':user_name}
            return None
        def signup_into_db(input_):
            """Signing up and insert the new user info"""
            with connect_db() as conn:
                reading_cursor = conn.execute("""
                SELECT EXISTS(
                    SELECT userid
                    FROM users
                    WHERE userid=?
                )""", (input_.get('user_id'),))
                result = reading_cursor.fetchone()
                if result is None:
                    debug_flash('unknown error. db is unable to fetch')
                elif result[0] == 1:
                    debug_flash('there is already such id')
                else:
                    inserting_cursor = conn.cursor()
                    inserting_cursor.execute(
                        """
                        INSERT INTO users
                        (userid, username, passwd_hash, authority)
                        VALUES
                        (?, ?, ?, ?)
                        """,
                        (input_.get('user_id'),
                         input_.get('user_name'),
                         input_.get('passwd_hash'),
                         'admin'))
                    conn.commit()

                    asserting_cursor = conn.execute("""
                    SELECT passwd_hash
                    FROM users
                    WHERE userid=?
                    """, (input_.get('user_id'),))
                    result = asserting_cursor.fetchone()
                    if not (result is None) and  result[0] == input_.get('passwd_hash'):
                        return True
            return False

        input_ = validate_input()
        if input_ is None:
            return redirect_itself
        else:
            if signup_into_db(input_):
                debug_flash('sign up success')
                next_target = request.args.get('next')
                if not is_safe_redirect_url(next_target):
                    return abort(400)
                return redirect(next_target or url_for('index'))
            else:
                debug_flash('sign up failed')
                return redirect_itself

@app.route('/settings')
@login_required
def settings():
    """Test for authority"""
    return render_template_with_pid('settings.html')
@app.route('/about')
def about():
    """Test for misc pages"""
    return render_template_with_pid('about.html')

if __name__ == '__main__':
    app.run(debug=True)
