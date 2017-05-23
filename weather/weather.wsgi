import os
import sys
import site

# Add the site-packages of the chosen virtualenv to work with
site.addsitedir('/home/lgm/flaskplayground/weather/gimunvenv/lib/python2.7/site-packages')

# Add the app's directory to the PYTHONPATH
sys.path.append('/home/lgm/flaskplayground/weather')
#sys.path.append('/home/django_projects/MyProject/myproject')

# Activate your virtual env
activate_env = os.path.expanduser("/home/lgm/flaskplayground/weather/gimunvenv/bin/activate_this.py")
execfile(activate_env, dict(__file__=activate_env))

from app import app as application
