import json
import xmltodict


def translatejson(inputjson, dictionary):
    if type(inputjson) is dict and dictionary.endswith('.json'):
        translationjson = getobj(dictionary)
        getjsonpath(inputjson, translationjson)

        return translationjson
    else:
        print("Not JSON format")


# Get paths from JSON with paths
def getobj(filename):
    with open(filename) as jtemp:
        jsonpaths = json.load(jtemp)

    return jsonpaths


# Find values (via formatlist) in the input JSON we need for our output JSON
def findattributes(xmljson, formatjson):
    for key in formatjson:
        if formatjson[key]:
            formatjson[key] = getjsonval(xmljson, formatjson[key].split('/'))


# Recursively find path in translation JSON
def getjsonpath(inputjson, translationjson):
    for key, value in translationjson.items():
        if type(value) is dict:
            getjsonpath(inputjson, translationjson[key])
            continue
        else:
            translationjson[key] = getjsonval(inputjson, translationjson[key].split('/'))


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
        return injson[nextpathname]


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
        print('Format not supported')


# JSON to XML
def jsontoxml(filename):
    xmlobj = xmltodict.unparse(filename)

    return xmlobj


# XML to JSON
def xmltojson(filename):
    jsonobj = xmltodict.parse(filename.read())

    return json.dumps(jsonobj)
