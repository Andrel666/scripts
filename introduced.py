#this runs only in pyhon 2 (python 3 needs to replace urllib2)
#run only for vulns, not license. -> Licenses does not have disclosure date

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
      "orgs": [
        "4c503fed-f788-41f5-bdcb-55bb41188364"
      ],
      "severity": [
        "high",
        "medium",
        "low"
      ],
      "exploitMaturity": [
        "mature",
        "proof-of-concept",
        "no-known-exploit",
        "no-data"
      ],
      "types": [
        "vuln"
      ],
      "languages": [
        "javascript",
        "ruby",
        "java",
        "scala",
        "python",
        "golang",
        "php",
        "dotnet"
      ],
      "projects": [
         "fd6a96fa-e2b1-40a7-9b51-c776c3cfa2ca","4a7505ae-bd3d-4c31-9512-7887e3774aca"
      ],
      "isFixed": false

    }
  }
"""

headers = {
  'Content-Type': 'application/json',
  'Authorization': '7db595c1-675a-4394-83fc-a182b76c38d5'
}
request = Request('https://snyk.io/api/v1/reporting/issues/?from=2019-04-01&to=2020-02-02', data=values, headers=headers)

response_body = urlopen(request).read()

#vulns = json.loads(response_body)
vulns = json_loads_byteified(response_body)

ii = 0
for vul in vulns['results']:
    print (vulns["results"][ii]['issue']['id']) ,"disclosure: \t", (vulns["results"][ii]['issue']['disclosureTime']), " \tintroduced : " ,(vulns["results"][ii]['introducedDate'])

    ii= ii+1
