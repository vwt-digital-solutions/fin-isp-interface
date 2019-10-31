import json

from translation import translate
from translation import invoice


class DBProcessor(object):
    def __init__(self):
        pass

    def process(self, payload):
        print(json.dumps(payload))
        self.translatetoxml(payload)

    def translatetoxml(self, invoicejson):
        # Fill additional fields invoice
        invoice.enrichdata(invoicejson['Invoice'])

        # Translate to output JSON
        outputjson = translate.translatejson(invoicejson, 'translation.json')

        # Translate to XML for ISP
        print(translate.translatexmljson(outputjson))
