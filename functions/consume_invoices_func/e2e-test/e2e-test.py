import config
import datetime
import logging
import sys
import json

from google.cloud import storage, logging as cloud_logging

PROJECT_ID = sys.argv[1]
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


def get_log_entries():
    # Set Logger client
    cloud_client = cloud_logging.Client()
    log_name = 'cloudfunctions.googleapis.com%2Fcloud-functions'
    cloud_logger = cloud_client.logger(log_name)

    # Set logging filter
    cur_timestamp = datetime.datetime.utcnow().strftime(
        "%Y-%m-%dT%H:%M:%S.%f")
    log_filter = "severity = INFO " + \
                 f"AND resource.labels.function_name = " + \
                 f"\"{FUNCTION_NAME}\" " + \
                 f"AND timestamp > \"{cur_timestamp}-05:00\" " + \
                 "AND textPayload: \"invoice sent\""

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

    try:
        get_log_entries()
        provide_files()
    except TimeoutError as e:
        logging.error(
            'An exception occurred: {}.'.format(e))
        sys.exit(1)
