from flask import Flask, request
import logging
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
LOGFILE = os.environ.get('LOGFILE', '/var/log/alertmanager_webhook.log')

@app.route('/', methods=['GET'])
def index():
    return 'Test receiver OK', 200

@app.route('/', methods=['POST'])
def receive_alert():
    data = request.get_json(silent=True)
    logging.info('Received alert: %s', data)
    try:
        with open(LOGFILE, 'a') as f:
            f.write(str(data) + '\n')
    except Exception as e:
        logging.error('Failed writing to logfile: %s', e)
    return '', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
