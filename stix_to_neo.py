import json
from os import getenv

from stix2validator import validate_file, print_results
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

        object_properties = {}
        for attr, value in stix_object.items():
            if isinstance(value, (dict,list)):
                object_properties[attr] = json.dumps(value)
            else:
                object_properties[attr] = value

        query = f"""
            MERGE (x:{label} {{id: "{stix_object["id"]}"}})
            SET x = $properties
        """

        session.run(query, properties=object_properties)


#TODO: Create a function for loading embedded relationships: Matrix, Tactics, Techniques
#main function to load SROs
def load_sros(path):
    with open(path) as f:
        stix_json_data = json.load(f)

    stix_relationships = [rel for rel in stix_json_data["objects"] if rel["type"] in "relationship"]

    for stix_relationship in stix_relationships:

        relationship_name = to_pascal_case(stix_relationship["relationship_type"])

        relationship_properties = {}
        for attr, value in stix_relationship.items():
            if isinstance(value, (dict, list)):
                relationship_properties[attr] = json.dumps(value)
            else:
                relationship_properties[attr] = value

        query = f"""
            MATCH (sourceObject {{id: "{stix_relationship["source_ref"]}"}}), (targetObject {{id: "{stix_relationship["target_ref"]}"}})
            MERGE (sourceObject)-[r:{relationship_name}]->(targetObject)
            SET r = $properties
        """
        session.run(query, properties=relationship_properties)


def to_pascal_case(input_string):
  words = input_string.split('-')
  pascal_case_string = "".join(word.capitalize() for word in words)

  return pascal_case_string


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
    load_mobile("attack-stix-data/mobile-attack-17.1.json")
    load_enterprise("attack-stix-data/enterprise-attack-17.1.json")

driver.close()
