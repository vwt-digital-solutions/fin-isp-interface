import json
import xmltodict
import logging


def translatejson(inputjson, dictionary):
    translationjson = getobj(dictionary)
    getjsonpath(inputjson, translationjson)

    return translationjson


# Get paths from JSON with paths
def getobj(filename):
    with open(filename) as jtemp:
        jsonpaths = json.load(jtemp)

    return jsonpaths


# Recursively find path in translation JSON
def getjsonpath(inputjson, translationjson):
    for key, value in translationjson.items():
        if type(value) is dict:
            getjsonpath(inputjson, translationjson[key])
            continue
        else:
            valueforpath = getjsonval(inputjson, translationjson[key].split('/'))
            if valueforpath != 'Not part of JSON Invoice':
                translationjson[key] = valueforpath


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
def translatexmljson(file):

    if type(file) is dict:
        return jsontoxml(file)

    elif type(file) is str:
        with open(file) as temp:
            if file.endswith('.json'):
                jsonobj = json.load(temp)
                return jsontoxml(jsonobj)

            elif file.endswith('.xml'):
                return xmltojson(temp)

    else:
        logging.info('Format not supported')


# JSON to XML
def jsontoxml(filename):
    xmlobj = xmltodict.unparse(filename)

    return xmlobj


# XML to JSON
def xmltojson(filename):
    jsonobj = xmltodict.parse(filename.read())

    return json.dumps(jsonobj)
