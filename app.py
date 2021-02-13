import os
import redis
import datetime
from flask import Flask, request, redirect, url_for, render_template, flash
from celery import Celery
from imohash import hashfile
from api.api import VtScanAPI, API_KEY
from werkzeug.utils import secure_filename

# Flask App declaration and settings
app = Flask(__name__)
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'
# Set the secret key to some random bytes. Keep this really secret!
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# File Upload settings and Allowed Extensions
UPLOAD_FOLDER = './uploads/'
ALLOWED_EXTENSIONS = {'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Celery Message Broker and Task Runner Config
celery = Celery(app.name, backend=app.config['CELERY_RESULT_BACKEND'], broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# Global Dict Data Structures to Store Async Task Objects and related methods
task_dict = dict()


# Redis Server Setup for Caching
def redis_connect():
    try:
        client = redis.Redis(
            host="localhost",
            port=6379,
            db=0,
            socket_timeout=5,
        )
        ping = client.ping()
        if ping is True:
            return client
    except redis.AuthenticationError as rd_auth_err:
        raise redis.AuthenticationError("Invalid Auth!")


redis_client = redis_connect()


def get_results_list():
    result_links = list()
    for key in task_dict.keys():
        disp_list_contents = {
            'file_name' : task_dict[key]['file_name'],
            'hash_key': task_dict[key]['hash_key'],
            'time_crated': task_dict[key]['time_crated'],
        }
        result_links.append(disp_list_contents)
    return result_links


# Async Methods to Scan the API
@celery.task
def get_scan_report(file_path):
    scan_obj = VtScanAPI(API_KEY, file_path)
    scan_report = scan_obj.get_report(redis_client)
    return {'result': scan_report}


# Flask Methods for Routes
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files or request.files['file'].filename == '':
            flash(u'Invalid File POST. Please only post text files')
            return redirect(request.url)

        file = request.files['file']
        filename = secure_filename(file.filename)

        if '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)

            report_obj = get_scan_report.delay(file_path)
            file_name_hash = hashfile(file_path, hexdigest=True)[:7]

            task_dict[file_name_hash] = {'report_obj': report_obj, 'file_name': filename,
                                         'time_crated': str(datetime.datetime.now()), 'hash_key': file_name_hash
                                         }
            return redirect(url_for('result_list'))
        else:
            flash(u'Invalid File Type')
            return redirect(request.url)
    else:
        return render_template('upload_file.html')


@app.route('/results/')
def result_list():
    return render_template('result_list.html', links_list=get_results_list())


@app.route('/results/<file_hash>')
def display_results(file_hash):
    if task_dict[file_hash]['report_obj'].ready() is True:
        results = task_dict[file_hash]['report_obj'].get()['result']
        return render_template('display_results.html', results=results)
    else:
        # TODO: Render a Processing Icon
        return "Still Processing Please check back later."


if __name__ == '__main__':
    app.debug = True
    app.run()
