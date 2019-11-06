import requests
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
        xml_file = f"/tmp/{name}" + ".xml"

        client = kms_v1.KeyManagementServiceClient()

        # Get the passphrase for the private key
        pk_passphrase = client.crypto_key_path_path(os.environ['GCP_PROJECT'], 'europe-west1',
                                                    os.environ['GCP_PROJECT'] + '-keyring',
                                                    config.ISPINVOICES_KEY_PASSPHRASE)
        response = client.decrypt(pk_passphrase, open('passphrase.enc', "rb").read())

        passphrase = response.plaintext.decode("utf-8").replace('\n', '')

        # Get the private key and decode using passphrase
        pk_enc = client.crypto_key_path_path(os.environ['GCP_PROJECT'],
                                             'europe-west1',
                                             os.environ['GCP_PROJECT'] + '-keyring',
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

        # Write XML to file
        tree = ET.ElementTree(ET.fromstring(xml))

        tree.write(xml_file, encoding='utf8', xml_declaration=True, method='xml')

        # Get hostname for corresponding company
        url = config.URLS[self.companycode]

        # Send XML and PDF to share for test ISP
        pdf = {'pdf': (pdf_file, open(pdf_file, 'rb'))}

        headers = {
            'Accept': "application/pdf",
            'Filename': name
        }
        rxml = requests.post(url, headers=headers, data=xml, cert=cert, verify=True)
        rpdf = requests.post(url, headers=headers, files=pdf, cert=cert, verify=True)

        if not rxml.ok:
            print("Failed to upload XML invoice")
        else:
            print("XML invoice sent")

        if not rpdf.ok:
            print("Failed to upload PDF invoice")
        else:
            print("PDF invoice sent")

    def translatetoxml(self, invoicejson):
        invoice.enrichdata(invoicejson['Invoice'])

        # Get company code
        self.companycode = invoicejson['Invoice']['Data']['CompCodeFin']

        # Translate to output JSON
        outputjson = translate.translatejson(invoicejson, 'translation.json')

        # Translate to XML for ISP
        return translate.translatexmljson(outputjson)
