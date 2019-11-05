# import requests
import os
import config
import xml.etree.cElementTree as ET

from translation import translate
from translation import invoice
from google.cloud import kms_v1

from OpenSSL import crypto


class DBProcessor(object):
    companycode = 'Not specified'

    def __init__(self):
        pass

    def process(self, payload):
        xml = self.translatetoxml(payload)
        name = 'testfile'
        pdf_file = name + '.pdf'

        client = kms_v1.KeyManagementServiceClient()

        # Get the passphrase for the private key
        pk_passphrase = client.crypto_key_path_path(os.environ['GOOGLE_CLOUD_PROJECT'], 'europe-west1',
                                                    os.environ['GOOGLE_CLOUD_PROJECT'] + '-keyring',
                                                    config.ISPINVOICES_KEY_PASSPHRASE)
        response = client.decrypt(pk_passphrase, open('passphrase.enc', "rb").read())

        passphrase = response.plaintext.decode("utf-8").replace('\n', '')

        # Get the private key and decode using passphrase
        pk_enc = client.crypto_key_path_path(os.environ['GOOGLE_CLOUD_PROJECT'],
                                             'europe-west1',
                                             os.environ['GOOGLE_CLOUD_PROJECT'] + '-keyring',
                                             config.ISPINVOICES_KEY)
        response = client.decrypt(pk_enc, open('ispinvoice-pk.enc', "rb").read())

        # Write un-encrypted key to file (for requests library)
        pk = crypto.load_privatekey(crypto.FILETYPE_PEM, response.plaintext, passphrase.encode())

        key_file_path = "/tmp/key.pem"
        open(key_file_path, "w").write(
            str(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk, cipher=None, passphrase=None), 'utf-8'))

        # Create the HTTP POST request
        cert_file_path = "ispinvoice-cert.pem"
        cert = (cert_file_path, key_file_path)
        print(cert)

        # Write XML object to temporary file
        invoice_file_string = ET.tostring(xml, encoding="utf8", method="xml")
        invoice_file_name = f"/tmp/{name}" + ".xml"
        open(invoice_file_name, "w").write(str(invoice_file_string, 'utf-8'))

        # Get hostname for corresponding company
        url = config.URLS[self.companycode]
        print(url)

        multiple_files = {'xml': (name + '.xml', open(invoice_file_name, 'rb')), 'pdf': (name + '.pdf', open(pdf_file, 'rb'))}
        print(type(multiple_files))
        '''
        # Need to be able to post PDF and XML
        r = requests.post(config.ISPINVOICES_URL, files=multiple_files, cert=cert, verify=True)
        if not r.ok:
            print("Failed to upload XML invoice")
        else:
            print("XML invoice sent")
        '''

    def translatetoxml(self, invoicejson):
        # Fill additional fields invoice
        invoice.enrichdata(invoicejson['Invoice'])

        # Get company code
        self.companycode = invoicejson['Invoice']['Data']['CompCodeFin']

        # Translate to output JSON
        outputjson = translate.translatejson(invoicejson, 'translation.json')

        # Translate to XML for ISP
        print(translate.translatexmljson(outputjson))
