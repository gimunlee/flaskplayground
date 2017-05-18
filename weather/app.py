"""The entry of flask app"""
import sqlite3
from datetime import datetime
from urlparse import urlparse, urljoin
from flask import Flask, render_template, request, redirect, session, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user, AnonymousUserMixin # pylint: disable=import-error

def is_safe_redirect_url(target):
    """Validate the url"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
            ref_url.netloc == test_url.netloc

class WeatherUser(UserMixin):
    """Custom User class"""
    def temp(self):
        """temp function"""
        print 'temp : ' + self.get_id()
    def __init__(self, userid, name):
        # flash('init(%s,%s)'% (userid, name))
        self.id = userid
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
app.config.from_pyfile('./settings.py', silent=True)
app.secret_key = "asdklfnci;ovz"
if app.debug:
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 1
    print 'debug mode on'

login_manager = LoginManager() # pylint: disable=invalid-name
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    """Loader for login manager"""
    return WeatherUser.get(user_id)
login_manager.login_view = 'login'

def debug_flash(msg):
    """Flash a message with the timestamp for debug"""
    flash(str(datetime.now()) + ": " + msg)

def connect_db():
    """Connect to the db enlisted in the config"""
    return sqlite3.connect(app.config['DATABASE'])

def query_rows(size):
    """Query rows of given size."""
    with connect_db() as conn:
        cursor = conn.execute("""
        SELECT *
          FROM tbl_weather
         LIMIT ?;
        """, (size,))
        result = cursor.fetchall()
    return result
def query_limit_offset(limit, offset):
    """Query rows of limit, after the offset"""
    result = None
    with connect_db() as conn:
        cursor = conn.execute("""
        SELECT *
          FROM tbl_weather
         LIMIT ?
        OFFSET ?;
        """, (limit, offset))
        result = cursor.fetchall()
    return result
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
        # cursor = conn.
        # cursor = conn.execute("""
        #    SELECT basicdate, local_name, precipitation, avg_snow, min_temperature, max_temperature, avg_temperature
        #      FROM tbl_weather
        # LEFT JOIN tbl_local_info
        #        ON tbl_weather.local_code = tbl_local_info.local_code
        #  ORDER BY basicdate
        #     LIMIT ?
        #    OFFSET ?
        # """, (limit, offset))
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

@app.route('/')
def index():
    """Index page"""
    # return str(len(query_rows(_MILLION)))
    # flash('username : ' + str(session.get('username')))

    offset = request.args.get('offset')
    
    return render_template(
        'index.html',
        is_logged_in=session.get('is_logged_in'),
        username=session.get('username'),
        count=query_count(),
        weather_table=query_full_info(10, offset or 0)
    )
# @app.route('/query')
# def query():
#     """General query"""
#     limit = request.args.get('limit')
#     offset = request.args.get('offset')

#     sql_statement = """
#     SELECT * FROM tbl_weather
#     """
#     if limit:
#         sql_statement += """LIMIT :limit """
#         if offset:
#             sql_statement += """OFFSET :offset"""

#     with connect_db() as conn:
#         cursor = conn.execute(sql_statement, {"limit": limit, "offset": offset})
#         result = cursor.fetchall()
#     return str(len(result)) + ' rows quieried.'

@app.route('/login', methods=['GET', 'POST'])
def login():
    """login"""
    if request.method == 'POST':
        # validate_form()
        user_id = request.form.get('user_id')
        user = WeatherUser.get(user_id)
        if(user is None):
            debug_flash('The user id does not exist')
            return redirect(url_for('index'))

        if login_user(user):
            debug_flash('Logged in as %s successfully.' % str(user.name))

            next = request.args.get('next')
            if not is_safe_redirect_url(next):
                return abort(400)
            return redirect(next or url_for('index'))
        else:
            return render_template('login.html')
    else:
        return render_template('login.html')
@app.route('/logout')
@login_required
def logout():
    """logout"""
    result = logout_user()
    if result:
        debug_flash('logged out successfully')
    # flash(current_user.name)
    return redirect(url_for('index'))

@app.route('/settings')
@login_required
def settings():
    """Test for authority"""
    return render_template('settings.html')

if __name__ == '__main__':
    app.run(debug=True)
