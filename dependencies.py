from urllib2 import Request, urlopen
import json

def json_load_byteified(file_handle):
    return _byteify(
        json.load(file_handle, object_hook=_byteify),
        ignore_dicts=True
    )

def json_loads_byteified(json_text):
    return _byteify(
        json.loads(json_text, object_hook=_byteify),
        ignore_dicts=True
    )
#function to get string without unicode u prefix
def _byteify(data, ignore_dicts = False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data



values = """
  {
    "filters": {
      "languages": [
        "javascript",
        "ruby",
        "java",
        "dotnet"
      ],
      "projects": ["e6c7705d-b912-4c92-b71e-54408b8401a1", "99c21081-070d-4fd4-bb7e-36572d01da55"],
      "dependencies": [],
      "licenses": [],
      "severity": [
        "high",
        "medium",
        "low"
      ],
      "depStatus": ""
    }
  }
"""

headers = {
  'Content-Type': 'application/json',
  'Authorization': 'YOUR-TOKEN'
}
request = Request('https://snyk.io/api/v1/org/4c503fed-f788-41f5-bdcb-55bb41188364/dependencies', data=values, headers=headers)

response_body = urlopen(request).read()
#print response_body#
#dep = json.loads(response_body)
dep = json_loads_byteified(response_body)

ii = 0
for deps in dep['results']:
    #print (dep["results"][ii]['id']), "\t"
    #print (dep['results'][ii]['id']) ,'\t', (dep['results'][ii]['name']) ,'\t', (dep['results'][ii]['version']) ,'\t', (dep['results'][ii]['type']),'\t'
    depId = (dep['results'][ii]['id'])
    depName = (dep['results'][ii]['name'])
    depVer = (dep['results'][ii]['version'])
    depType = (dep['results'][ii]['type'])
    iii=0
    for lics in dep['results'][ii]['licenses']:
      #print (dep['results'][ii]['licenses'][iii]['id']) , '\t' ,dep['results'][ii]['licenses'][iii]['title'] ,'\t' , dep['results'][ii]['licenses'][iii]['license']
      licId = (dep['results'][ii]['licenses'][iii]['id'])
      licTitle = dep['results'][ii]['licenses'][iii]['title']
      licLicense = dep['results'][ii]['licenses'][iii]['license']
      iii=iii+1
    copy = ""
    if 'copyright' in dep['results'][ii]:
      #print (dep['results'][ii]['copyright'])
      copy =  (dep['results'][ii]['copyright'])
        #reset iii for loop on projs
    iii=0
    for projs in dep['results'][ii]['projects']:
      #print (dep['results'][ii]['projects'][iii]['id']) , '\t' ,dep['results'][ii]['projects'][iii]['name'] ,'\t'
      projID = (dep['results'][ii]['projects'][iii]['id'])
      projName = dep['results'][ii]['projects'][iii]['name']
      iii=iii+1
      #print projID , "t" , projName, "\t" , licId , "\t", licTitle , "\t", licLicense , "\t" , depName, "\t", depVer , "\t"
    ii= ii+1
