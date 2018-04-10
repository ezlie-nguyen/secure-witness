from datetime import datetime, timedelta
import time
from django.conf import settings
from django.contrib import auth

# from http://stackoverflow.com/questions/14830669/how-to-expire-django-session-in-5minutes

class AutoLogout:
  def process_request(self, request):
    if not request.user.is_authenticated() :
      #Can't log out if not logged in
      return

    try:
      if time.time() - request.session['last_touch'] > timedelta( 0, settings.AUTO_LOGOUT_DELAY, 0).seconds:
        auth.logout(request)
        del request.session['last_touch']
        return
    except KeyError:
      pass

    request.session['last_touch'] = time.time()