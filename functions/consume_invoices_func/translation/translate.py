import json
import xmltodict
import logging


def translatejson(input_json, dictionary):
    translation_json = getobj(dictionary)
    getjsonpath(input_json, translation_json)

    return translation_json


# Get paths from JSON with paths
def getobj(filename):
    with open(filename) as jtemp:
        jsonpaths = json.load(jtemp)

    return jsonpaths


# Recursively find path in translation JSON
def getjsonpath(input_json, translation_json):
    for key, value in translation_json.items():
        if type(value) is dict:
            getjsonpath(input_json, translation_json[key])
            continue
        else:
            valueforpath = getjsonval(input_json, translation_json[key].split('/'))
            if valueforpath != 'Not part of JSON Invoice':
                translation_json[key] = valueforpath


# Recursively find value in input JSON
def getjsonval(injson, path):
    nextpathname = path[0]
    if path[1:]:
        # Handle lists for duplicate keys/tags in json
        if nextpathname.endswith(']'):
            return getjsonval(injson[nextpathname[:-3]][int(nextpathname[-2:-1])], path[1:])
        else:
            return getjsonval(injson[nextpathname], path[1:])
    else:
        try:
            return injson[nextpathname]
        except KeyError:
            return 'Not part of JSON Invoice'


# Automatically translate xml to json or json to xml
def translate_xml_json(file):

    if type(file) is dict:
        return json_to_xml(file)

    elif type(file) is str:
        with open(file) as temp:
            if file.endswith('.json'):
                jsonobj = json.load(temp)
                return json_to_xml(jsonobj)

            elif file.endswith('.xml'):
                return xml_to_json(temp)

    else:
        logging.info('Format not supported')


# JSON to XML
def json_to_xml(filename):
    xmlobj = xmltodict.unparse(filename)

    return xmlobj


# XML to JSON
def xml_to_json(filename):
    jsonobj = xmltodict.parse(filename.read())

    return json.dumps(jsonobj)
