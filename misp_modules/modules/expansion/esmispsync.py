import json
import re
import requests
from requests.auth import HTTPBasicAuth

# Parameter die durch Admin-Konfiguration gesetzt werden
moduleconfig = ["elk_host", "elk_user", "elk_pass"]

misperrors = {'error': 'Error'}
mispattributes = {'input': ['md5'], 'output': ['data']}
moduleinfo = {
    'version': '0.1',
    'author': 'Markus Schätzle',
    'module-type': ['expansion'],
    'name': 'CSV Import',
    'description': 'Module to enrich event with threat-data from abusech stored in elasticsearch',
    'requirements': ['PyMISP'],
    'features': "Hello, there are no features yet :(",
    'input': 'MD5-Hash',
    'output': 'Threat-Data',
    'logo': '',
}

class ESMISPSYNC:
    def __init__(self, elk_user='elastic', elk_pass='x=JEtzV7CJJIVnSrxn7i', elk_host='172.23.2.20:9200', md5_hash="0006ad7b9f2a9b304e5b3790f6f18807"):
        # Variablen
        self.elk_user = elk_user
        self.elk_pass = elk_pass
        elk_host = elk_host

        # URL für die Anfrage
        self.url = f'https://{elk_host}/logs-ti_abusech.*/_search'

        # Header für die Anfrage
        self.headers = {
            "Accept": "application/json"
        }

        # Body der Anfrage als Dictionary
        self.query = {
            "_source": ["abusech", "related", "threat"],
            "query": {
                "match": {
                    "threat.indicator.file.hash.md5": md5_hash
                }
            }
        }


    def send_request(self):
        # Sende die Anfrage mit HTTP Basic Authentifizierung
        response = requests.get(self.url, headers=self.headers, auth=HTTPBasicAuth(self.elk_user, self.elk_pass), json=self.query, verify=False)

        # Antwort auslesen
        data = response.text

        # JSON-Antwort in ein Dictionary umwandeln
        parsed_data = json.loads(data)

        self.found_data = parsed_data['hits']['hits']
        
        return self.format_data()

    
    def format_data(self):
        ti_data = {
            "downloads":        -1,
            "uploads":          -1,
            "tags":             -1,
                    
            "geo":              -1,
            "first-seen":       -1,
            "extension":        -1,
            "file_type":        -1,
                
            "size":             -1,
            "mime":             -1,
            "hashes":           -1,
            "name":             -1,
            "type":             -1,
            
            "related_hashes":   -1,
                    
            "virustotal_result":-1,
            "virustotal_link":  -1
        }
        
        for entry in self.found_data:
            data = entry["_source"]
            source_key = list(data["abusech"].keys())[0]
            
            d1 = data["abusech"][source_key]
            d2 = data["threat"]["indicator"]
            
            if source_key == "malwarebazaar":
                rest_data = {
                    "downloads":        d1["intelligence"]["downloads"],
                    "uploads":          d1["intelligence"]["uploads"],
                    "tags":             d1["tags"],
                    "geo":              d2["geo"]["country_iso_code"],
                    "first-seen":       d2["first_seen"],
                    "extension":        d2["file"]["extension"],
                    "size":             d2["file"]["size"],
                    "mime":             d2["file"]["mime_type"],
                    "hashes":           d2["file"]["hash"],
                    "name":             d2["file"]["name"],
                    "type":             d2["type"],
                    "related_hashes":   data["related"]["hash"]
                }
            elif source_key == "malware":
                rest_data = {
                    "virustotal_result":d1["virustotal"]["result"],
                    "virustotal_link":  d1["virustotal"]["link"],
                    "first-seen":       d2["first_seen"],
                    "file_type":        d2["file"]["type"],
                    "size":             d2["file"]["size"],
                    "hashes":           d2["file"]["hash"],
                    "type":             d2["type"],
                    "related_hashes":   data["related"]["hash"]
                }
            else:
                print(f'[!] Error, could not find key {source_key}!')
                
            for key in rest_data:
                ti_data[key] = rest_data[key]
            
        return ti_data


def value_exists_in_result_data(search_value, result_data):
    for entry in result_data:
        if entry.get('values') == search_value:
            return True
    return False


def identify_hash(hash_value):
    # Dictionary zum Speichern von möglichen Hash-Längen und deren Typen
    hash_types = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512'
    }
    
    # Erkennung von TLSH (length is typically 70+)
    if re.match(r'^[A-F0-9]{70,}$', hash_value):
        return 'tlsh'
    
    # Erkennung von SSDEEP (contains a ':' character)
    if ':' in hash_value:
        return 'ssdeep'
    
    # Identifizierung durch Länge des Hash-Werts
    hash_length = len(hash_value)
    if hash_length in hash_types:
        return hash_types[hash_length]
    
    # Wenn kein Typ erkannt wird
    return 'unknown'


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    # Eine Anfrage muss mindestens den md5 enthalten
    if not request.get('md5'):
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    
    # Wenn eine Anfrage über die GUI erfolgt, ist die config enthalten
    if request.get('config'):
        event_id  = request['event_id']
        attr_uuid = request['attribute_uuid']
        elk_user  = request['config']['elk_user']
        elk_pass  = request['config']['elk_pass']
        elk_host  = request['config']['elk_host']
        elk_md5   = request['md5']
        
        try:
            response = ESMISPSYNC(elk_user, elk_pass, elk_host, request['md5']).send_request()
        except requests.exceptions.ConnectionError:
            misperrors['error'] = "Failed to establish connection to elasticsearch"
            return misperrors
        
        ti_data = {
            "downloads":    {'comment':"Anzahl heruntergeladen", 'type':"counter", 'category': "Other"},
            "uploads":      {'comment':"Anzahl hochgeladen", 'type':"counter", 'category': "Other"},
            "tags":         {'comment':"verwandte tags", 'type':"text", 'category': "Payload delivery"},
                    
            "geo":          {'comment':"Herkunft", 'type':"other", 'category': "Payload delivery"},
            "first-seen":   {'comment':"Zuerst gesehen", 'type':"datetime", 'category': "Other"},
            "extension":    {'comment':"Dateierweiterung (exe, bat, ...)", 'type':"text", 'category': "Other"},
            "file_type":    {'comment':"Daten/Dokumenttyp", 'type':"", 'category': "Payload delivery"},
                
            "size":         {'comment':"Dateigröße", 'type':"size-in-bytes", 'category': "Other"},
            "mime":         {'comment':"Mime-type", 'type':"mime-type", 'category': "Payload delivery"},
            "hashes":       {'comment':"verwandte Hashes", 'type':"", 'category': "Payload delivery"},
            "name":         {'comment':"Dateiname", 'type':"text", 'category': "Other"},
            "type":         {'comment':"Dateityp", 'type':"text", 'category': "Other"},
            
            "related_hashes": {'comment':"verwandte Hashes", 'type':"", 'category': "Payload delivery"},
                    
            "virustotal_result": {'comment':"Bewertung durch Virustotal", 'type':"text", 'category': "Other"},
            "virustotal_link":   {'comment':"Link auf Eintrag in Virustotal", 'type':"link", 'category': "Internal reference"}
        }
        
        result_data = []
        for key, value in response.items():
            # Unbekannter Schlüssel in response
            if key not in ti_data:
                misperrors['error'] = "Malformed reponse, unknown keys in data"
                return misperrors
            
            # Response enthält Informationen
            if value != -1:
                if key == 'hashes':
                    for hash_key, hash_value in value.items():
                        if hash_key == 'md5':
                            continue
                        if not value_exists_in_result_data(hash_value, result_data):
                            result_data.append({
                                'types': hash_key,
                                'values': hash_value,
                                'comment': ti_data[key]['comment'],
                                'category': ti_data[key]['category'],
                            })
                elif key == 'related_hashes':
                    for hash_value in value:
                        if identify_hash(hash_value) == 'md5':
                            continue
                        if not value_exists_in_result_data(hash_value, result_data):
                            result_data.append({
                            'types': identify_hash(hash_value),
                            'values': hash_value,
                            'comment': ti_data[key]['comment'],
                            'category': ti_data[key]['category'],
                        })
                else:
                    if not value_exists_in_result_data(value, result_data):
                        result_data.append({
                            'types': ti_data[key]['type'],
                            'values': value,
                            'comment': ti_data[key]['comment'],
                            'category': ti_data[key]['category'],
                        })
        return {'results': result_data}
    else:
        # Erlaube keine Anfrage über Konsole
        misperrors['error'] = "Too few data"
        return misperrors
    
    return {'results': response}
                
def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo