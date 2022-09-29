import flask

from controller import *

app = flask.Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///miniCloud2.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
db.init_app(app)
with app.app_context():
    print("create_vm")
    print(create_vm("efc11e8c-bce8-5b8c-bf48-5ac3c6957c75", "dynamic", "1C1G", "test1", "liyumin", "123456"))
    print("create_nat")
    print(create_nat("dynamic", "10.0.5.6", 10022, 22, "tcp"))
