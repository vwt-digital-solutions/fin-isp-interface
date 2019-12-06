import config
import datetime
import logging
import sys
import json
import uuid
import time

from google.cloud import storage, pubsub_v1, logging as cloud_logging

PROJECT_ID = sys.argv[1]
BUILD_ID = sys.argv[2]
FUNCTION_NAME = sys.argv[3]


def time_format(dt):
    return "%s:%.3f%sZ" % (
        dt.strftime('%Y-%m-%dT%H:%M'),
        float("%.3f" % (dt.second + dt.microsecond / 1e6)),
        dt.strftime('%z')
    )


def provide_files():
    st_client = storage.Client(project=config.E2E_STORAGE_BUCKET_PROJECT_ID)
    bucket = st_client.bucket(config.E2E_STORAGE_BUCKET_NAME)

    filename = '{}/e2e-test/e2e_test.pdf'.format(
        config.E2E_STORAGE_BUCKET_FOLDER)
    blob_exists = storage.Blob(bucket=bucket, name=filename).exists(st_client)
    if not blob_exists:
        blob = bucket.blob(filename)
        with open("assets/e2e_test.pdf", "rb") as my_file:
            blob.upload_from_file(my_file,
                                  content_type='application/pdf')
        logging.info('Uploaded E2E-PDF to bucket {}'.format(
            config.E2E_STORAGE_BUCKET_NAME))
    else:
        logging.info('E2E-PDF exists in bucket {}'.format(
            config.E2E_STORAGE_BUCKET_NAME))


def set_message_content(payload, unique_id):
    cur_timestamp = datetime.datetime.utcnow()
    payload['gobits'][0]['gcp_project'] = PROJECT_ID
    payload['gobits'][0]['execution_id'] = BUILD_ID
    payload['gobits'][0]['execution_name'] = '{}-e2e-test'.format(PROJECT_ID)
    payload['gobits'][0]['timestamp'] = cur_timestamp.strftime(
        "%Y-%m-%dT%H:%M:%S.%f")
    payload['invoice']['process_date'] = cur_timestamp.strftime(
        "%Y-%m-%d")
    payload['invoice']['invoice_number'] = unique_id

    return payload


def post_message_to_topic(unique_id):
    publisher = pubsub_v1.PublisherClient()
    topic_name = 'projects/{project_id}/topics/{topic}'.format(
        project_id=config.E2E_TOPIC_PROJECT_ID,
        topic=config.E2E_TOPIC_NAME)

    with open('assets/e2e_test_message.json', 'r') as json_file:
        message = set_message_content(json.load(json_file), unique_id)

    publisher.publish(topic_name,
                      bytes(json.dumps(message).encode('utf-8')))
    logging.info('Message for E2E-invoice "{}" has been posted to {}'.format(
        unique_id, topic_name))


def request_log(cloud_logger, unique_id):
    cur_timestamp = time_format(
        (datetime.datetime.utcnow() - datetime.timedelta(seconds=60)))
    log_filter = "severity = INFO " + \
                 f"AND resource.labels.function_name = " + \
                 "\"{}\" ".format(FUNCTION_NAME) + \
                 "AND timestamp >= \"{}\" ".format(cur_timestamp) + \
                 "AND textPayload: \"[{}]\"".format(unique_id)

    entries = cloud_logger.list_entries(
        filter_=log_filter, order_by=cloud_logging.DESCENDING,
        projects=[PROJECT_ID])

    return entries


def get_log_entries(unique_id):
    cloud_client = cloud_logging.Client()
    log_name = 'cloudfunctions.googleapis.com%2Fcloud-functions'
    cloud_logger = cloud_client.logger(log_name)

    start_time = time.time()
    is_existing = {'pdf': False, 'xml': False}
    while True:
        if time.time() - start_time > 60:
            raise TimeoutError('No matching logs found')
        else:
            logging.info('Refreshing logs...')
            entries = request_log(cloud_logger=cloud_logger,
                                  unique_id=unique_id)

            for entry in entries:
                logging.info('Found logging: {}'.format(entry.payload))
                if 'PDF invoice sent' in entry.payload:
                    is_existing['pdf'] = True
                elif 'XML invoice sent' in entry.payload:
                    is_existing['xml'] = True

            if is_existing['pdf'] and is_existing['xml']:
                logging.info('Both files succesful posted')
                break
            else:
                time.sleep(15.0 - ((time.time() - start_time) % 15.0))


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)

    # Set uniqueness ID for invoice-number
    unique_id = str(uuid.uuid4())

    try:
        provide_files()
        post_message_to_topic(unique_id=unique_id)
        get_log_entries(unique_id=unique_id)
    except TimeoutError as e:
        logging.error(
            'An timeout occurred: {}.'.format(e))
        sys.exit(1)
