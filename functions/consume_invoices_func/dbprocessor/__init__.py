import requests
import os
import config
import logging
import tempfile
from PyPDF2 import PdfFileReader, PdfFileWriter
from translation import translate
from google.cloud import kms_v1, storage
from OpenSSL import crypto


class DBProcessor(object):

    file_name_merged = "merged"

    def __init__(self):
        self.companycode = ''
        self.url = ''
        self.file_name = ''
        self.base_path = ''
        self.bucket_name = ''
        self.invoice_number = ''
        self.client = storage.Client()
        pass

    def process(self, payload):
        xml = self.translatetoxml(payload)
        pdf_name = self.merge_pdf_files()

        pdf_file_tmp = f"/tmp/{self.file_name}.pdf"

        # Retrieving PDF file from bucket
        bucket = self.client.get_bucket(self.bucket_name)
        blob = bucket.get_blob(f"{self.base_path}{pdf_name}.pdf")
        blob.download_to_filename(pdf_file_tmp)

        # Prepare PDF and XML for sending
        pdf = {'pdf': (self.file_name, open(pdf_file_tmp, 'rb'))}
        headerspdf = {
            'Content-Type': "application/pdf",
            'Accept': "application/pdf",
            'Filename': self.file_name
        }

        headersxml = {
            'Content-Type': "application/xml",
            'Accept': "application/xml",
            'Filename': self.file_name
        }

        # Key and certificate for request
        cert = self.getcertificate()

        # Posting XML data and PDF file to server in separate requests
        rxml = requests.post(self.url, headers=headersxml, data=xml, cert=cert, verify=True)
        if not rxml.ok:
            logging.info("[{}] Failed to upload XML invoice".format(
                self.invoice_number))
        else:
            logging.info("[{}] XML invoice sent".format(self.invoice_number))

            rpdf = requests.post(self.url, headers=headerspdf, files=pdf, cert=cert, verify=True)
            if not rpdf.ok:
                logging.info("[{}] Failed to upload PDF invoice file".format(
                    self.invoice_number))
            else:
                logging.info("[{}] PDF invoice sent".format(
                    self.invoice_number))

    def merge_pdf_files(self):
        bucket = self.client.get_bucket(self.bucket_name)
        blobs = self.client.list_blobs(self.bucket_name, prefix=self.base_path)

        pdf_files = []
        for blob in blobs:
            if blob.name.endswith('.pdf'):
                if blob.name != self.file_name:
                    pdf_files.append(blob)
                else:
                    pdf_files = [blob] + pdf_files

        if len(pdf_files) == 1:
            return self.file_name

        writer = PdfFileWriter()  # Create a PdfFileWriter to store the new PDF
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as merged_pdf:
            for pdf in pdf_files:
                content_as_string = pdf.download_as_string()

                # Write PDF content to tempfile so we can read and add all pages to merged PDF
                with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as pdf_merge:
                    pdf_merge.write(content_as_string)
                    pdf_merge.close()
                    reader = PdfFileReader(open(pdf_merge.name, 'rb'))
                    [writer.addPage(reader.getPage(i)) for i in range(0, reader.getNumPages())]  # Add pages

                logging.info(f"Merged file: {pdf.name.split('/')[-1]}")

            writer.write(merged_pdf)

        merged_pdf.close()
        content = open(merged_pdf.name, 'rb').read()  # Read the content from the temp file

        blob = bucket.blob(f"{self.base_path}{self.file_name_merged}.pdf")
        blob.upload_from_string(
                content,  # Upload content
                content_type="application/pdf"
            )

        return self.file_name_merged

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

    def translatetoxml(self, invoice_json):
        # Get company code and filename from JSON
        self.invoice_number = invoice_json['invoice']['invoice_number']
        self.buildfilename(invoice_json)
        self.companyrouting(invoice_json)

        # Translate to output JSON
        outputjson = translate.translatejson(invoice_json, 'translation.json')

        # Translate to XML for ISP
        return translate.translate_xml_json(outputjson)

    # Get hostname for corresponding company
    def companyrouting(self, invoice_json):
        # Company code
        self.companycode = invoice_json['invoice']['company_id']

        # Make URL from dictionary in config
        self.url = config.HOSTNAME + invoice_json['invoice']['url_extension']

    def buildfilename(self, invoicejson):
        # Get bucketname for PDF file and general filename for both XML and PDF
        if 'stg' in invoicejson['invoice']['pdf_file']:

            partnames = invoicejson['invoice']['pdf_file'][:-4].split('/')

            self.bucket_name = partnames[2]
            self.file_name = partnames[-1]
            self.pdf_file = invoicejson['invoice']['pdf_file'].split(f"{self.bucket_name}/")[1]
            self.base_path = invoicejson['invoice']['pdf_file'].split(f"{self.bucket_name}/")[1].split(f"{self.file_name}")[0]

            invoicejson['invoice']['pdf_file'] = self.file_name
        else:
            logging.info("[{}] PDF not in bucket".format(self.invoice_number))
