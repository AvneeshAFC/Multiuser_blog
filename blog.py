import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'arsenalfc'     # A secret code to make sure the respective
# hash is safe from hackers


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
    # returns the val and hmac of the argument


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):  # validation
        return val


class BlogHandler(webapp2.RequestHandler):
    """
        A parent class for the handlers
    """

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

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

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# def render_post(response, post):
    # response.out.write('<b>' + post.subject + '</b><br>')
    # response.out.write(post.content)


class MainPage(BlogHandler):

    def get(self):
        #self.write('Hello, Udacity!')
        self.redirect("/blog")


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))
    # generates a random 5 letter string for future use


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Like(db.Model):
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    # Both post_id and user_id are required in order
    # for like to work

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name


class Comment(db.Model):
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    # All the above entities are required at the same time
    # for the comment functionality to work in the blog

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name


class Post(db.Model):
    user_id = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    # All these attributes are required before publishing
    # or modification of blog posts

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class BlogFront(BlogHandler):

    def get(self):
        deleted_post_id = self.request.get('deleted_post_id')
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")
        # ^ The above Gql retrieves renders 10 recent blog posts
        self.render('front.html', posts=posts, deleted_post_id=deleted_post_id)


class PostPage(BlogHandler):
    """
        This class is responsible for displaying blog post related information
        like the post itself, no. of likes, comments etc
Reference : https://discussions.udacity.com/t/multi-blog-comment-section/281301
    """

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        likes = db.GqlQuery("select * from Like where post_id=" + post_id)
        # ^ gql query to select the records from the like model of a post
        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc limit 10")
        # ^ gql query to retrieve the comment data of a specific post

        if not post:
            self.error(404)
            return

        error = self.request.get('error')

        self.render("permalink.html", post=post, Likes=likes.count(),
                    comments=comments, error=error)
        # ^ renders the permalink.html page with the post, likes, comments

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        com = ""        # Empty initialization of com iterator
        if(self.user):
            if(self.request.get('like') and
                    self.request.get('like') == "update"):
                likes = db.GqlQuery("select * from Like where post_id = " +
                                    post_id + " and user_id = " + str(self.user.key().id()))
            # This links the like clicked with the current logged in user
            # and the specific post on which the like is pressed & increments

                if self.user.key().id() == post.user_id:
                    self.redirect("/blog/" + post_id + "?error=Dont't be " +
                                  "greedy :p. You can't like your own post")
                    return
                elif likes.count() == 0:
                    like = Like(parent=blog_key(),
                                user_id=self.user.key().id(), post_id=int(post_id))
                    like.put()  # Stores the like in the data store

            if(self.request.get('comment')):
                com = Comment(parent=blog_key(), user_id=self.user.key().id(),
                              post_id=int(post_id), comment=self.request.get('comment'))
                com.put()
                # The comment made is linked with the logged in user's info
                # on the specific post
        else:
            error = "Error : You need to login to interact with the posts"
            self.redirect("/login?")
            return

        likes = db.GqlQuery("select * from Like where post_id=" + post_id)
        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")

        self.render("permalink.html", post=post,
                    comments=comments, Likes=likes.count(), new=com)
        # Freshly renders the permalink.html with posts, likes, comments


class NewPost(BlogHandler):
    """
        A handler to create new blog posts with the respective logged in user
    """

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), user_id=self.user.key().id(),
                     subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Fill in both the subject and the content"
            self.render(
                "newpost.html",
                subject=subject,
                content=content,
                error=error)


class ModifyPost(BlogHandler):
    """
        Class to edit/modify a specific post written by the logged in
        user only.
    """

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                return self.redirect("/login")
            if post.user_id == self.user.key().id():
                self.render("postedit.html", subject=post.subject,
                            content=post.content)
                # postedit.html is rendered if the userid matches
            else:
                self.redirect("/blog/" + post_id + "?error=Error : " +
                              "You can't modify other's post")
        else:
            self.redirect("/login")
            # Redirected to the log in page if not signed in to the blog
            error = "Login to continue.."

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')  # Request for blog post title
        content = self.request.get('content')  # Request for blog post content

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                return self.redirect("/login")
            if not post.user_id == self.user.key().id():
                return self.redirect("/login")
            post.subject = subject      # Updation of title
            post.content = content      # Updation of content
            post.put()                  # Stored in the data store
            self.redirect('/blog/%s' % post_id)         # Redirects to the post
        else:
            error = "Fill in both the subject and the content"
            # Error is thrown when one or more details are left blank
            self.render("postedit.html", subject=subject,
                        content=content, error=error)


class DelPost(BlogHandler):
    """
        Class to delete a specific post written by the logged in user only.
        Note that a user can't delete posts of another user.
    """

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                return self.redirect("/login")
            if post.user_id == self.user.key().id():
                post.delete()  # If the user_id matches, post is deleted
                self.redirect("/?deleted_post_id=" + post_id)
            else:
                self.redirect("/blog/" + post_id + "?error=Error : " +
                              "You can't delete other's post")
        else:
            self.redirect("/login")
            # Redirected to the login page if a non-signed in user tries
            # to delete any post
            error = "Login to continue.."


class ModifyComment(BlogHandler):
    """
        Class to edit/modify a particular comment made by the logged in
        user on any blog post.
    """

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            com = db.get(key)
            if not com:
                return self.redirect("/login")
            if com.user_id == self.user.key().id():
                self.render("commentedit.html", comment=com.comment)
                # if user id matches, commentedit.html is loaded
            else:
                self.redirect("/blog/" + post_id +
                              "?error=Error : You can't modify other's " +
                              "comments")
        else:
            error = "Log in to continue.."
            # Redirected to the the login page if not logged in
            self.redirect("/login?")

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/blog')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment',
                                   int(comment_id), parent=blog_key())
            com = db.get(key)
            if not com:
                return self.redirect("/login")
            if not com.user_id == self.user.key().id():
                return self.redirect("/login")
            com.comment = comment   # Updation of comment takes place
            com.put()               # Updation stored in the data store
            self.redirect('/blog/%s' % post_id)
        else:
            error = "Fill in both the details"
            # Error is shown if any detail is left blank. The written
            # detail is retained as it is.
            self.render("postedit.html", subject=subject,
                        content=content, error=error)


class DelComment(BlogHandler):
    """
        Class to delete a particular comment made by the logged in user
        on any post.
    """

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            com = db.get(key)
            if not com:
                return self.redirect("/login")
            if com.user_id == self.user.key().id():  # Validation
                com.delete()    # Comment deletion upon matching the user_id
                self.redirect("/blog/" + post_id + "?deleted_comment_id=" +
                              comment_id)
            else:
                self.redirect("/blog/" + post_id + "?error=Error : You " +
                              "can't delete another user's comments")
                # Error thrown when trying to delete other's comments
        else:
            error = "Login to continue.."
            # Redirected to the Sign in page if the user is logged out
            self.redirect("/login")


# Form Validation for the signup page
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

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


class Unit2Signup(Signup):

    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


class Register(Signup):

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/blog')

# class Unit3Welcome(BlogHandler):
#    def get(self):
#        if self.user:
#            self.render('welcome.html', username = self.user.name)
#        else:
#            self.redirect('/signup')


class Welcome(BlogHandler):

    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')

# Handlers for different functionalities in the blog
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/postedit/([0-9]+)', ModifyPost),
                               ('/blog/delpost/([0-9]+)', DelPost),
                               ('/blog/commentedit/([0-9]+)/([0-9]+)',
                                ModifyComment),
                               ('/blog/delcomment/([0-9]+)/([0-9]+)',
                                DelComment),
                               ('/unit2/signup', Signup)
                               ],
                              debug=True)
