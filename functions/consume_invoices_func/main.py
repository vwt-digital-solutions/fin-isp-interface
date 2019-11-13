import logging
import json
import base64
import os

from dbprocessor import DBProcessor

import config

parser = DBProcessor()
verification_token = os.environ['PUBSUB_VERIFICATION_TOKEN']
domain_token = config.DOMAIN_VALIDATION_TOKEN


def topic_to_xml(request):
    if request.method == 'GET':
        return '''
             <html>
                 <head>
                     <meta name="google-site-verification" content="{token}" />
                 </head>
                 <body>
                 </body>
             </html>
         '''.format(token=domain_token)

    if request.args.get('token', '') != verification_token:
        return 'Invalid request', 400

    # Extract data from request
    envelope = json.loads(request.data.decode('utf-8'))
    payload = base64.b64decode(envelope['message']['data'])
    print("Published on: " + envelope['message']['publishTime'])

    # Extract subscription from subscription string
    try:
        subscription = envelope['subscription'].split('/')[-1]
        logging.info(f'Message received from {subscription} [{payload}]')

        parser.process(json.loads(payload))

    except Exception as e:
        logging.info('Extract of subscription failed')
        logging.debug(e)

    # Returning any 2xx status indicates successful receipt of the message.
    # 204: no content, delivery successful, no further actions needed
    return 'OK', 204
