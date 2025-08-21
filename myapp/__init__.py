# __init__.py
from dotenv import load_dotenv
import os
from flask_mail import Mail, Message
# Загружаем переменные окружения из файла .env в корневой директории
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '..', '.env'))

from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_moment import Moment
from flask_dance.contrib.google import make_google_blueprint, google
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)
moment = Moment(app)
from myapp import routes, models
from myapp.admin import admin_bp

app.register_blueprint(admin_bp)
google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    #scope=["profile", "email"],
    redirect_to="google_login",
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ]
)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' #чисто для разработки пон
app.register_blueprint(google_bp, url_prefix="/login")
mail = Mail(app)