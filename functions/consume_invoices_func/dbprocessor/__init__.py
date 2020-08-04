import os
import json
import config
import logging
import tempfile
import requests

from . import translate_error
from translation import translate
from PyPDF2 import PdfFileReader, PdfFileWriter
from google.cloud import secretmanager_v1, storage
from OpenSSL import crypto
from gobits import Gobits

TranslateError = translate_error.TranslateError


class DBProcessor(object):

    def __init__(self):
        self.companycode = ''
        self.url = ''
        self.file_name = ''
        self.file_metadata = 'metadata.json'
        self.base_path = ''
        self.bucket_name_einvoices = ''
        self.bucket_name_isp = config.BUCKET_NAME
        self.invoice_number = ''
        self.merged_pdf = None
        self.client = storage.Client()
        pass

    def process(self, payload, in_request, message):
        try:
            xml = self.translate_to_xml(payload)

            # Get files from einvoices bucket
            bucket_einvoices = self.client.get_bucket(self.bucket_name_einvoices)
            blobs = self.client.list_blobs(bucket_einvoices, prefix=self.base_path)

            bits = Gobits(request=in_request, message=message)
            gobits = bits.to_json()

            try:
                if self.file_name != "e2e_test":
                    self.check_metadata(gobits)
            except TranslateError:
                raise
            else:
                self.create_merged_pdf(blobs)

            logging.info("Prepare XML and PDF for sending")
            pdf = {'pdf': (self.file_name, open(self.merged_pdf.name, 'rb'))}
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

            cert = self.get_certificates()

            # Posting XML data and PDF file to server in separate requests
            logging.info("Send XML and PDF to ISP")
            rxml = requests.post(self.url, headers=headersxml, data=xml, cert=cert, verify=True)
            if not rxml.ok:
                raise TranslateError(4001, function_name="process",
                                     fields=[rxml],
                                     description=f"Invoice {self.invoice_number}: XML post request to ISP failed")
            else:
                logging.info("[{}] XML invoice sent".format(self.invoice_number))

                rpdf = requests.post(self.url, headers=headerspdf, files=pdf, cert=cert, verify=True)
                if not rpdf.ok:
                    raise TranslateError(4001, function_name="process",
                                         fields=[rpdf],
                                         description=f"Invoice {self.invoice_number}: PDF post request to ISP failed")
                else:
                    logging.info("[{}] PDF invoice sent".format(
                        self.invoice_number))

            # Remove (content) temp file
            self.merged_pdf.close()
            os.unlink(self.merged_pdf.name)

            # Update metadata
            self.update_metadata(gobits, payload['gobits'])

        except TranslateError as e:
            if e.properties['error']['exception_id'] == 4030:
                logging.info(json.dumps({'warning': e.properties['error']}))
            else:
                logging.error(json.dumps(e.properties))
        except Exception as e:
            logging.exception(e)

    def check_metadata(self, gobits):
        bucket_isp = self.client.get_bucket(self.bucket_name_isp)
        blob_metadata = bucket_isp.blob(self.base_path + self.file_metadata)
        if blob_metadata.exists():
            metadata = json.loads(blob_metadata.download_as_string())
            for step in metadata['gobits']:
                if step.get('message_id', '') == gobits['message_id'] and \
                 step.get('gcp_project', '') == gobits['gcp_project']:
                    raise TranslateError(4030, function_name="check_metadata",
                                         fields=[gobits['message_id'], gobits['gcp_project']],
                                         description=f"Invoice {self.invoice_number}: Message has already been processed")

            raise TranslateError(4000, function_name="check_metadata", fields=["message_id"],
                                 description=f"Invoice {self.invoice_number}: Message has duplicate path but different message IDs")

        blob_mergedpdf = bucket_isp.blob(f"{self.base_path}{self.file_name}.pdf")
        if blob_mergedpdf.exists():
            raise TranslateError(4000, function_name="check_metadata", fields=["message_id"],
                                 description=f"Invoice {self.invoice_number}: Merged PDF already exists")

    def update_metadata(self, gobits, payload_gobits):
        bucket_isp = self.client.get_bucket(self.bucket_name_isp)
        blob = bucket_isp.blob(self.base_path + self.file_metadata)
        metadata = {
            "gobits": payload_gobits + [gobits]
        }
        blob.upload_from_string(json.dumps(metadata),
                                content_type='application/json')

    def create_merged_pdf(self, blobs):
        bucket_isp = self.client.get_bucket(self.bucket_name_isp)
        pdf_files = []

        for blob in blobs:
            if blob.name.endswith('.pdf'):
                if blob.name != self.pdf_file:
                    pdf_files.append(blob)
                else:
                    pdf_files = [blob] + pdf_files

        if len(pdf_files) == 1:
            content = pdf_files[0].download_as_string()
            with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as self.merged_pdf:
                self.merged_pdf.write(content)
        else:
            content = self.merge_pdf_files(pdf_files)

        try:
            blob = bucket_isp.blob(f"{self.base_path}{self.file_name}.pdf")

            if not blob.exists():
                blob.upload_from_string(
                    content,  # Upload content
                    content_type="application/pdf"
                )
                logging.info(f"Merged file uploaded to storage: {self.file_name}.pdf")
        except Exception as e:
            logging.error("An error occured during uploading blob: {}".format(e))

    def merge_pdf_files(self, pdf_files):
        writer = PdfFileWriter()  # Create a PdfFileWriter to store the new PDF

        with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as self.merged_pdf:
            for pdf in pdf_files:
                content_as_string = pdf.download_as_string()
                # Write PDF content to tempfile so we can read and add all pages to merged PDF
                with tempfile.NamedTemporaryFile(mode='w+b') as pdf_merge:
                    pdf_merge.write(content_as_string)
                    reader = PdfFileReader(pdf_merge.name)
                    [writer.addPage(reader.getPage(i)) for i in range(0, reader.getNumPages())]  # Add pages
                    logging.info(f"Merged file: {pdf.name.split('/')[-1]}")

            writer.write(self.merged_pdf)

        content = open(self.merged_pdf.name, 'rb').read()

        return content  # Return the content from the temp file

    def get_secret(self, project_id, secret_id):

        client = secretmanager_v1.SecretManagerServiceClient()

        secret_name = client.secret_version_path(
            project_id,
            secret_id,
            'latest')

        response = client.access_secret_version(secret_name)
        payload = response.payload.data.decode('UTF-8')

        return payload

    def make_temp(str):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write(str)

        return temp_file

    def get_certificates(self):

        passphrase = self.get_secret(os.environ['GCP_PROJECT'], config.PASSPHRASE)
        key = self.get_secret(os.environ['GCP_PROJECT'], config.KEY)
        certificate = self.get_secret(os.environ['GCP_PROJECT'], config.CERTIFICATE)

        pk = crypto.load_privatekey(crypto.FILETYPE_PEM, key, passphrase.encode())

        key_file = self.make_temp(
            str(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk, cipher=None, passphrase=None), 'utf-8'))

        cert_file = self.make_temp(certificate)

        return (cert_file, key_file)

    def translate_to_xml(self, invoice_json):
        # Get company code and filename from JSON
        self.invoice_number = invoice_json['invoice']['invoice_number']
        self.get_filename(invoice_json)
        self.company_routing(invoice_json)

        # Translate to output JSON
        output_json = translate.translatejson(invoice_json, 'translation.json')

        # Translate to XML for ISP
        return translate.translate_xml_json(output_json)

    # Get hostname for corresponding company
    def company_routing(self, invoice_json):
        # Company code
        self.companycode = invoice_json['invoice']['company_id']

        # Make URL from dictionary in config
        self.url = config.HOSTNAME + invoice_json['invoice']['url_extension']

    def get_filename(self, invoice_json):
        # Get bucketname for PDF file and general filename for both XML and PDF
        if 'stg' in invoice_json['invoice']['pdf_file']:

            name_build = invoice_json['invoice']['pdf_file'][:-4].split('/')

            self.bucket_name_einvoices = name_build[2]
            self.file_name = name_build[-1]
            self.pdf_file = invoice_json['invoice']['pdf_file'].split(f"{self.bucket_name_einvoices}/")[1]
            self.base_path = invoice_json['invoice']['pdf_file'].split(f"{self.bucket_name_einvoices}/")[1].split(f"{self.file_name}")[0]

            invoice_json['invoice']['pdf_file'] = self.file_name
        else:
            logging.info("[{}] PDF not in bucket".format(self.invoice_number))
