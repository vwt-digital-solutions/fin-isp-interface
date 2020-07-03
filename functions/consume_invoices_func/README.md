# JSON to XML
This function converts a JSON to XML, and posts it to a server. This function is the last step in a chain of functions and is intended to react to messages posted on a Pub/Sub Topic that has the structure as [written below](#ncoming-message)

To use this function both a ```config.py``` file (see [config.example.py](config/config.example.py) for an example) and a ```translation.json``` file (see [translation.example.json](config/translation.example.json) for an example) need to be defined to which configuration will be used.

## Setup
1. CRYPTO
2. Make sure a ```config.py``` file exists within the ```/config``` directory, based on the [config.example.py](config/config.example.py), with the correct configuration:
    ~~~
    DOMAIN_VALIDATION_TOKEN = A token used to validate the function endpoint to GCP
    HOSTNAME_TEST = Location of server where to post to
    URLS = Dictionary of possible endpoints
    ~~~

3. Make sure a correct ```translation.json``` is within the ```dbprocessor``` directory. This will be used to coordinate the placement of the JSON values in the XML
5. Deploy the function to GCP as a HTTP triggered function as shown in the [cloudbuild.example.yaml](cloudbuild.example.yaml)
5. Make sure a Pub/Sub Topic pushes to the function
6. Make sure you are allowed to post to HOSTNAME_TEST via a certificate
7. Make sure you are allowed to access the GCP bucket where the corresponding PDF is located

## Function
The consume-invoices function works as follows:
1. A message will be received from a Pub/Sub Topic with the [correct structure](#incoming-message),
2. The function will extract the JSON and loop over ```translation.json``` to transform the JSON structure to a nested XML structure, after which it translates the JSON to XML. It then ends up with the XML structure as [written below](#outgoing-xml)
3. Then it will get the PDF from a bucket (location is specified in the JSON object: ```[invoice][pdf_file]```) and ensures the XML file and PDF file have the same name
4. The files will then be sent to the server via separate post requests (including the certificate needed for security).


##### Incoming message
The message object received from a GCP Pub/Sub topic is defined as described below. For the gobits field, refer to [this](https://github.com/vwt-digital/gobits) repository.

~~~javascript
{
  "gobits": [previous_gobits, gobits],
  "invoice": {
    "field1": "value1",
    "field2": "value2",
    ...
  }
}
~~~

##### Outgoing XML
The XML structure sent to the server according to the [translation.example.json](config/translation.example.json) structure
~~~
<?xml version="1.0" encoding="utf-8"?>
<Invoice>
    <Header>
        <InvoiceNumber>123456</InvoiceNumber>
        <InvoiceDate>2000-01-01</InvoiceDate>
    </Header>
</Invoice>
~~~

## License
This function is licensed under the [GPL-3](https://www.gnu.org/licenses/gpl-3.0.en.html) License
