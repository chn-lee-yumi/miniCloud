import flask

import config
from controller import *

app = flask.Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///miniCloud3.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
db.init_app(app)

with app.app_context():
    print("refresh flow table")
    for node in config.compute_nodes:
        node = node_infos[node]
        node = db.session.query(Host).filter_by(management_ip=node["inventory_hostname"]).first()
        print(refresh_flow_table(node.uuid, Host))
    for node in config.network_nodes:
        node = node_infos[node]
        node = db.session.query(Gateway).filter_by(management_ip=node["inventory_hostname"]).first()
        print(refresh_flow_table(node.uuid, Gateway))
    for node in config.special_nodes:
        node = node_infos[node]
        node = db.session.query(SpecialNode).filter_by(management_ip=node["inventory_hostname"]).first()
        print(refresh_flow_table(node.uuid, SpecialNode))
