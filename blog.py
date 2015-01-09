import os
import re
import random
import hashlib
import hmac
import logging
import json
from string import letters
import time
import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.api import memcache
from time import strftime
from datetime import datetime

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'alkshfAAJLKJ(eaLJDEP9AEop.OUE.O'
REX = r'(/(?:[a-zA-Z0-9_-]+/?)*)?(?:\.json)?'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class MainHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def get_data(self, cache_key, update=False):
        result = memcache.get(cache_key)
        if result is None or update:
            if cache_key == '/':
                result = Page.all().order('-created')
            else:
                key = db.Key.from_path('Page', int(cache_key), parent= page_key())
                result = db.get(key)

            memcache.add_multi({cache_key: result,
                                '%s:cache_time' % cache_key: time.time()
                                }, 86400)
            logging.info('DB Query all posts')
        return result

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'


class MainPage(MainHandler):
    def get(self):
        self.write('Hello, Udacity!')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### wiki stuff
def page_key(name = 'default'):
    return db.Key.from_path('pages', name)

class Page(db.Model):
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    version = db.IntegerProperty()


    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self._render_text

    def as_dict(self):
        time_fmt = '%c'
        d = {'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d

    @staticmethod
    def parent_key(path):
        return db.Key.from_path('/root' + path, 'pages')

    @classmethod
    def by_path(cls, path):
        q = cls.all()
        q.ancestor(Page.parent_key(path))
        q.order('-created')
        return q

    @classmethod
    def by_id(cls, id, path):
        return cls.get_by_id(id, cls.parent_key(path))

    @classmethod
    def by_version(cls,path, version):
        q = cls.all()
        q.ancestor(Page.parent_key(path))
        q.filter('version =', version)
        return q

class Front (MainHandler):
    def get(self, path, update = False):
        cache_key = '/'
        posts = self.get_data(cache_key)
        start_time = memcache.get('%s:cache_time' % cache_key) or time.time()
        page = Page.by_path(path).get()
        if page and self.format == 'html':
            self.render("front.html", page=page, path=path, posts = posts, cached_time ="%.4f" %
                        (time.time() - start_time))
        elif page and self.format == 'json':
            self.render_json(page.as_dict())
        else:
            self.redirect('/_edit%s' % str(path))


class EditPage(MainHandler):
    def get(self, path):
        if not self.user:
            self.redirect('/login')

        v = self.request.params.get('v')
        p = None
        if v:
            if v.isdigit():
                p = Page.by_version(path, int(v)).get()
 
            if not p:
                self.error(404)
                self.write("The page you are looking for does NOT have a version: %s" % v)
                return
        else:
            p = Page.by_path(path).get()

        if not p:
            version = "0" # the version is 0 before a page is created
            self.render("editpage.html", page=None, path=path, version=version)
            return

        self.render("editpage.html", page=p, path=path, version=p.version)

    def post(self,path):
        if not self.user:
            self.redirect('/login')

        content = self.request.get('content')
        v = self.request.get('version')
        if not v:
            v = 0
        version = int(v) + 1 # the 1st version of page is set to 1 

        if content:
            p = Page(parent = Page.parent_key(path), content=content, version=version)
            p.put()
            self.redirect('..%s' % str(path))
        else:
            error = "Page content cannot be empty!"
            self.render("editpage.html", page=None, path=path, error=error)


class HistoryVersion(MainHandler):
    def get(self, path):
        cache_key = '/'
        posts = self.get_data(cache_key)
        start_time = memcache.get('%s:cache_time' % cache_key) or time.time()
        pages = Page.by_path(path)
        if pages:and self.format == 'html':
            self.render("history.html", page=page, path=path, posts = posts, cached_time ="%.4f" %
                        (time.time() - start_time))
        elif page and self.format == 'json':
            self.render_json(page.as_dict())



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(MainHandler):
    def get(self):
        next_url = str(self.request.referer)
        self.render("signup-form.html", next_url=next_url)

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)

        next_url = str(self.request.get('next_url'))
        if not next_url or next_url=='/signup':
            next_url = '/'

        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect(next_url)

class Login(MainHandler):
    def get(self):
        next_url = self.request.headers.get('referer', '/')
        self.render('login-form.html', next_url = next_url)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        
        next_url = str(self.request.get('next_url'))
        logging.info('next_url = %s' % next_url)
        if not next_url or next_url == '/login':
            next_url = '/'

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect(next_url)
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(MainHandler):
    def get(self):
        self.logout()
        self.redirect(self.request.referer)

class Welcome(MainHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Flush(MainHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/flush', Flush),
                               ('/_history' + REX , HistoryVersion),
                               ('/_edit' + REX , EditPage),
                               (REX, Front),
                               ],
                              debug=True)
