import os
import datetime
import json
import bcrypt

from flask import Flask, render_template, request, jsonify,send_from_directory,redirect,make_response,url_for

from google.cloud import datastore


def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = os.urandom(16)

    # blueprint for events routes
    from .events import events as events_blueprint
    app.register_blueprint(events_blueprint)

    # blueprint for auth routes
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # Add default route
    @app.route('/')
    def index():
        return redirect(url_for('events'))

    return app




if __name__ == '__main__':
    app = create_app()
    app.run(host ='127.0.0.1',port = 8080,debug=True)
