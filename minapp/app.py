"""The entry of flask app"""
from flask import Flask
from flask import render_template, flash

from datetime import datetime
from os import path, chdir, getpid
import sys

sys.stdout = sys.stderr
chdir(path.abspath(path.dirname(__file__)))

def render_template_with_pid(template, **args):
    """Add pid after the original arguments"""
    args['pid'] = getpid()
    return render_template(template, **args)

def debug_flash(msg):
    """Flash a message with the timestamp for debug"""
    if app.debug:
        flash(str(datetime.now()) + ": " + msg)

app = Flask(__name__) # pylint: disable=invalid-name
app.secret_key = "asdklfnci;ovz"

app.config.from_pyfile('./settings.py')
app.secret_key = "asdklfnci;ovz"
if app.debug:
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 1
    print 'debug mode'

@app.route('/')
def index():
    """Index page"""
    return render_template('index.html', msg="Hello")

if __name__ == '__main__':
    app.run(port=app.config.get('port') or 5000, debug=True)
    