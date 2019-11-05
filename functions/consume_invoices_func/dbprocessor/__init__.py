# import requests
import os
import config

from translation import translate
from translation import invoice
from google import kms_v1

from OpenSSL import crypto


class DBProcessor(object):
    def __init__(self):
        pass

    def process(self, payload):
        xmlf = self.translatetoxml(payload)
        pdf = ''

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
                                             os.environ['GOOGLE_CLOUD_PROJECT']+'-keyring',
                                             config.ISPINVOICES_KEY)
        response = client.decrypt(pk_enc, open('ispinvoice-pk.enc', "rb").read())

        # Write un-encrypted key to file (for requests library)
        pk = crypto.load_privatekey(crypto.FILETYPE_PEM, response.plaintext, passphrase.encode())

        key_file_path = "/tmp/key.pem"
        open(key_file_path, "w").write(str(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk, cipher=None, passphrase=None), 'utf-8'))

        # Create the HTTP POST request
        cert_file_path = "ispinvoice-cert.pem"
        cert = (cert_file_path, key_file_path)
        print(cert)

        name = 'testfile'
        xml_file = xmlf
        pdf_file = pdf

        multiple_files = {'xml': (name + '.xml', xml_file), 'pdf': (name + '.pdf', pdf_file)}
        print(multiple_files)
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

        # Translate to output JSON
        outputjson = translate.translatejson(invoicejson, 'translation.json')

        # Translate to XML for ISP
        print(translate.translatexmljson(outputjson))
