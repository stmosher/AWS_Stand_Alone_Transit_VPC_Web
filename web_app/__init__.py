from flask import Flask
from config import Config
from flask_bootstrap import Bootstrap
import logging


app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config.from_object(Config)

FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(handlers=[
    logging.FileHandler("{0}/{1}.log".format('./', 'log_web_app')),
    logging.StreamHandler()], format=FORMAT, level=logging.INFO)


from web_app import routes
