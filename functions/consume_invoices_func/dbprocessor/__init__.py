import requests
import os
import config
import xml.etree.cElementTree as ET

from translation import translate
from google.cloud import kms_v1, storage
from OpenSSL import crypto


class DBProcessor(object):
    companycode = 'Not specified'
    url = 'Not specified'
    filename = 'Not specified'
    pdf_file = 'Not specified'
    bucket_name = 'Not specified'

    def __init__(self):
        pass

    def process(self, payload):
        xml = self.translatetoxml(payload)

        # Same name for XML and PDF
        xml_file = f"/tmp/{self.filename}.xml"
        pdf_file_end = f"/tmp/{self.filename}.pdf"
        # Getting names from uri path

        # Retrieving PDF file from bucket
        client = storage.Client()
        bucket = client.get_bucket(self.bucket_name)
        blob = bucket.get_blob(self.pdf_file)
        blob.download_to_filename(pdf_file_end)

        # Write XML to file
        tree = ET.ElementTree(ET.fromstring(xml))
        tree.write(xml_file, encoding='utf8', xml_declaration=True, method='xml')

        # Prepare PDF and XML for sending
        pdf = {'pdf': (self.filename, open(pdf_file_end, 'rb'))}
        with open(xml_file) as xmlfi:
            xmldata = xmlfi.read()

        headerspdf = {
            'Content-Type': "application/pdf",
            'Accept': "application/pdf",
            'Filename': self.filename
        }

        headersxml = {
            'Content-Type': "application/xml",
            'Accept': "application/xml",
            'Filename': self.filename
        }

        # Key and certificate for request
        cert = self.getcertificate()

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

    def getcertificate(self):
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

        return cert_file_path, key_file_path

    def translatetoxml(self, invoicejson):
        # Get company code and filename from JSON
        self.buildfilename(invoicejson)
        self.companyrouting(invoicejson)

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

    def buildfilename(self, invoicejson):
        # Get bucketname for PDF file and general filename for both XML and PDF
        if 'stg' in invoicejson['invoice']['ScanTIFF']:
            partnames = invoicejson['invoice']['ScanTIFF'][:-4].split('/')

            self.bucket_name = partnames[2]
            self.filename = partnames[-2] + partnames[-1]

            self.pdf_file = invoicejson['invoice']['ScanTIFF'].split(f"{self.bucket_name}/")[1]

            invoicejson['invoice']['ScanTIFF'] = self.filename
        else:
            print("PDF not in bucket")
