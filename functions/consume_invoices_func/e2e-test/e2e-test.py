import config
import datetime
import logging
import sys
import json
import uuid

from google.cloud import storage, pubsub_v1, logging as cloud_logging

BUILD_ID = sys.argv[2]
FUNCTION_NAME = sys.argv[3]


def provide_files():
    st_client = storage.Client(project=config.E2E_STORAGE_BUCKET_PROJECT_ID)
    bucket = st_client.bucket(config.E2E_STORAGE_BUCKET_NAME)

    filename = '{}/e2e-test/e2e_test.pdf'.format(
        config.E2E_STORAGE_BUCKET_FOLDER)
    blob_exists = storage.Blob(bucket=bucket,
                               name=filename).exists(st_client)
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


def get_log_entries(unique_id):
    # Set Logger client
    cloud_client = cloud_logging.Client()
    log_name = 'cloudfunctions.googleapis.com%2Fcloud-functions'
    cloud_logger = cloud_client.logger(log_name)

    # Set logging filter
    cur_timestamp = datetime.datetime.utcnow().strftime(
        "%Y-%m-%dT%H:%M:%S.%f")
    log_filter = "severity = INFO " + \
                 f"AND resource.labels.function_name = " + \
                 "\"{}\" ".format(FUNCTION_NAME) + \
                 "AND timestamp > {} ".format(cur_timestamp) + \
                 "AND textPayload: \"[{}]\"".format(unique_id)

    # Retrieve logs
    all_entries = cloud_logger.list_entries(
        page_size=10, filter_=log_filter, order_by=cloud_logging.DESCENDING,
        projects=[PROJECT_ID])
    entries = next(all_entries.pages)

    # Check if logs contain correct invoice-number
    for entry in entries:
        timestamp = entry.timestamp.isoformat()
        logging.info('* {}: {}'.format(timestamp, entry.payload))


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
            'An exception occurred: {}.'.format(e))
        sys.exit(1)
