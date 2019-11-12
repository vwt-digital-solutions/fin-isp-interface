import requests
import os
import config
import xml.etree.cElementTree as ET

from translation import translate
from google.cloud import kms_v1

from OpenSSL import crypto


class DBProcessor(object):
    companycode = 'Not specified'
    url = 'Not specified'
    filename = 'Not specified'

    def __init__(self):
        pass

    def process(self, payload):
        xml = self.translatetoxml(payload)

        # Same name for XML and PDF
        pdf_file = self.filename + ".pdf"
        xml_file = f"/tmp/{self.filename}" + ".xml"

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

        cert_file_path = "ispinvoice-cert.pem"
        cert = (cert_file_path, key_file_path)

        # Write XML to file
        tree = ET.ElementTree(ET.fromstring(xml))
        tree.write(xml_file, encoding='utf8', xml_declaration=True, method='xml')

        # Prepare PDF and XML for sending
        pdf = {'pdf': (pdf_file, open(pdf_file, 'rb'))}

        with open(xml_file) as xmlfi:
            xmldata = xmlfi.read()

        # CHANGE FILENAME
        headerspdf = {
            'Content-Type': "application/pdf",
            'Accept': "application/pdf",
            'Filename': "testfile"                              # self.filename
        }
        # CHANGE FILENAME
        headersxml = {
            'Content-Type': "application/xml",
            'Accept': "application/xml",
            'Filename': "testfile"                              # self.filename
        }

        # Posting XML data and PDF file to server in separate requests
        rxml = requests.post(self.url, headers=headersxml, data=xmldata, cert=cert, verify=True)
        if not rxml.ok:
            print("Failed to upload XML invoice")
        else:
            print("XML invoice sent")

            rpdf = requests.post(self.url, headers=headerspdf, files=pdf, cert=cert, verify=True)
            if not rpdf.ok:
                print("Failed to upload PDF invoice file")
            else:
                print("PDF invoice sent")

    def translatetoxml(self, invoicejson):

        self.companyrouting(invoicejson)

        # Get company code and filename from JSON
        self.filename = invoicejson['invoice']['ScanTIFF']

        # Translate to output JSON
        outputjson = translate.translatejson(invoicejson, 'translation.json')

        # Translate to XML for ISP
        return translate.translatexmljson(outputjson)

    # Get hostname for corresponding company
    def companyrouting(self, invoicejson):
        # Company code
        self.companycode = invoicejson['invoice']['CompCodeFin']

        # Make URL from dictionary in config
        self.url = config.HOSTNAME_TEST + config.URLS[self.companycode]
