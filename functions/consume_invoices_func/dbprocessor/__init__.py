from google.cloud import datastore


class DBProcessor(object):
    def __init__(self):
        self.client = datastore.Client()
        pass

    def process(self, payload):
        print(payload['Metadata'])
        print(payload['Invoice']['InvoiceNumber'])
