import json
from os import getenv

from stix2.workbench import query
from stix2validator import validate_file, print_results
from stix2 import MemoryStore, Filter
from dotenv import load_dotenv
from neo4j import GraphDatabase


load_dotenv(".env")
db_uri = getenv("db_uri")
db_name = getenv("db_name")
db_username = getenv("db_username")
db_password= getenv("db_password")
auth = (db_username, db_password)
driver = GraphDatabase.driver(uri=db_uri, auth=auth)


#main function to load SDOs
def load_sdos(path):
    with open(path) as f:
        stix_json_data = json.load(f)

    stix_objects = [obj for obj in stix_json_data["objects"] if obj["type"] not in ("relationship", "x-mitre-collection")]

    for stix_object in stix_objects:

        label = to_pascal_case(stix_object["type"])
        merge_query = f"""
            MERGE (x:{label} {{id: "{stix_object["id"]}", type: "{stix_object["type"]}"}})
        """
        session.run(merge_query)

        for attr, value in stix_object.items():
            if isinstance(value, str):
                value = double_to_single_quotes(value)

            elif isinstance(value, (dict,list)):
                value = double_to_single_quotes(json.dumps(value))

            match_query = f"""
                MATCH (x:{label} {{id: "{stix_object["id"]}"}})
                SET x.{attr} = "{value}"
            """
            session.run(match_query)


#TODO: Make attributes load automatically just like in load_sdos
#TODO: Create a function for loading embedded relationships: Matrix, Tactics, Techniques
#main function to load SROs
def load_sros(path):
    with open(path) as f:
        stix_json_data = json.load(f)

    for stix_object in stix_json_data["objects"]:

        if stix_object["type"] == "relationship":
            relationship_name = to_pascal_case(stix_object["relationship_type"])

            query = f"""
                MATCH (sourceObject {{id: $id_source}}), (targetObject {{id: $id_target}})
                MERGE (sourceObject)-[r:{relationship_name}]->(targetObject)
                SET r.id = $id_relationship,
                    r.type = $type,
                    r.spec_version = $spec_version,
                    r.created = datetime($created),
                    r.modified = datetime($modified)
                """
            session.run(
                query,
                id_source=stix_object["source_ref"],
                id_target=stix_object["target_ref"],
                id_relationship=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"]
            )


def to_pascal_case(input_string):
  words = input_string.split('-')
  pascal_case_string = "".join(word.capitalize() for word in words)

  return pascal_case_string

def double_to_single_quotes(s):
    s = s.replace('\\"', "'")
    s = s.replace('"', "'")
    return s


with (driver.session(database=db_name) as session):

    def load_ics(path: str):
        # results = validate_file(path)
        # print_results(results)
        load_sdos(path)
        load_sros(path)

    def load_mobile(path: str):
        # results = validate_file(path)
        # print_results(results)
        load_sdos(path)
        load_sros(path)

    def load_enterprise(path: str):
        # results = validate_file(path)
        # print_results(results)
        load_sdos(path)
        load_sros(path)

    load_ics("attack-stix-data/ics-attack-17.1.json")
    #load_mobile("attack-stix-data/mobile-attack-17.1.json")
    #load_enterprise("attack-stix-data/enterprise-attack-17.1.json")

driver.close()
