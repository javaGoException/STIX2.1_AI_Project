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
        object_properties = get_stix_properties_dict(stix_object)

        query = f"""
            MERGE (x:{label} {{id: "{stix_object["id"]}"}})
            SET x = $properties
        """

        session.run(query, properties=object_properties)


#main function to load SROs
def load_sros(path):
    with open(path) as f:
        stix_json_data = json.load(f)

    stix_relationships = [rel for rel in stix_json_data["objects"] if rel["type"] in "relationship"]

    for stix_relationship in stix_relationships:

        relationship_name = to_pascal_case(stix_relationship["relationship_type"])
        relationship_properties = get_stix_properties_dict(stix_relationship)

        query = f"""
            MATCH (sourceObject {{id: "{stix_relationship["source_ref"]}"}}), (targetObject {{id: "{stix_relationship["target_ref"]}"}})
            MERGE (sourceObject)-[r:{relationship_name}]->(targetObject)
            SET r = $properties
        """
        session.run(query, properties=relationship_properties)


#main function to load embedded relationships
def load_embedded_relationships(path):
    with open(path) as f:
        stix_json_data = json.load(f)

    ###Matrices to Tactics###

    matrix_objects = [obj for obj in stix_json_data["objects"] if obj["type"] == "x-mitre-matrix"]

    for matrix_obj in matrix_objects:

        for tactic_ref_id in matrix_obj["tactic_refs"]:

            relationship_type = "ReferencesTactic"

            relationship_properties = {
                "relationship_type": relationship_type,
                "source_ref": matrix_obj["id"],
                "target_ref": tactic_ref_id
            }

            query = f"""
                MATCH (sourceObject {{id: "{matrix_obj["id"]}"}}), (targetObject {{id: "{tactic_ref_id}"}})
                MERGE (sourceObject)-[r:{relationship_type}]->(targetObject)
                SET r = $properties
            """
            session.run(query, properties=relationship_properties)

    ###Tactics to Techniques###

    tactic_shortname_to_id = {}
    for obj in stix_json_data["objects"]:
        if obj["type"] == "x-mitre-tactic" and "x_mitre_shortname" in obj:
            tactic_shortname_to_id[obj["x_mitre_shortname"]] = obj["id"]

    attack_patterns = [obj for obj in stix_json_data["objects"] if obj["type"] == "attack-pattern"]

    for attack_pattern in attack_patterns:
        attack_pattern_id = attack_pattern["id"]

        if attack_pattern.get("kill_chain_phases"):
            for phase in attack_pattern["kill_chain_phases"]:
                phase_name = phase["phase_name"]

                if phase_name in tactic_shortname_to_id:
                    tactic_id = tactic_shortname_to_id[phase_name]

                    relationship_type = "ContainsTechnique"

                    relationship_properties = {
                        "relationship_type": relationship_type,
                        "source_ref": tactic_id,
                        "target_ref": attack_pattern_id,
                        "kill_chain_name": phase.get("kill_chain_name")
                    }

                    query = f"""
                            MATCH (sourceObject {{id: "{tactic_id}"}}), (targetObject {{id: "{attack_pattern_id}"}})
                            MERGE (sourceObject)-[r:{relationship_type}]->(targetObject)
                            SET r = $properties
                        """
                    session.run(query, properties=relationship_properties)


def to_pascal_case(input_string):
  words = input_string.split('-')
  pascal_case_string = "".join(word.capitalize() for word in words)

  return pascal_case_string

def get_stix_properties_dict(stix_dict):

    properties = {}
    for attr, value in stix_dict.items():
        if isinstance(value, (dict, list)):
            properties[attr] = json.dumps(value)
        else:
            properties[attr] = value

    return properties

with (driver.session(database=db_name) as session):

    def load_ics(path: str):
        results = validate_file(path)
        print_results(results)
        #load_sdos(path)
        #load_sros(path)
        #load_embedded_relationships(path)

    def load_mobile(path: str):
        results = validate_file(path)
        print_results(results)
        #load_sdos(path)
        #load_sros(path)
        #load_embedded_relationships(path)

    def load_enterprise(path: str):
        results = validate_file(path)
        print_results(results)
        #load_sdos(path)
        #load_sros(path)
        #load_embedded_relationships(path)

    load_ics("attack-stix-data/ics-attack-17.1.json")
    #load_mobile("attack-stix-data/mobile-attack-17.1.json")
    #load_enterprise("attack-stix-data/enterprise-attack-17.1.json")

driver.close()