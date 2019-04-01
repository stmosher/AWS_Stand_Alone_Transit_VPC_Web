from flask_login import UserMixin
from web_app import login
import os


class User(UserMixin):
    def __init__(self,  username, password):
        self.username = username
        self.password = password
        self.id = self.set_id()

    def set_id(self):
        if self.username == os.environ.get('web_username'):
            return '1'
        else:
            return '2'

    def check_password(self, password_from_form):
        if self.password == password_from_form:
            return True
        else:
            return False


@login.user_loader
def load_user(id):
    if id == '1':
        return User(username=os.environ.get('web_username'), password=os.environ.get('web_password'))
    else:
        return None

