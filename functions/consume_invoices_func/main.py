import logging
import json
import base64

from dbprocessor import DBProcessor

parser = DBProcessor()
logging.basicConfig(level=logging.INFO)


def topic_to_xml(request):
    # Extract data from request
    envelope = json.loads(request.data.decode('utf-8'))
    message = envelope['message']
    payload = base64.b64decode(message['data'])

    # Extract subscription from subscription string
    try:
        subscription = envelope['subscription'].split('/')[-1]
        logging.info(f'Message received from {subscription} [{payload}]')

        parser.process(json.loads(payload), request, message)

    except Exception as e:
        logging.info('Extract of subscription failed')
        logging.debug(e)
        raise e

    # Returning any 2xx status indicates successful receipt of the message.
    # 204: no content, delivery successful, no further actions needed
    return 'OK', 204
