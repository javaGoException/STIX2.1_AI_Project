import json
import ast
import os
from os import getenv
from stix2validator import validate_file, print_results
from dotenv import load_dotenv
from neo4j import GraphDatabase

# --- Start of setup code (moved from 1_prep.py context) ---
load_dotenv(".env")
db_uri = getenv("db_uri")
db_name = getenv("db_name")
db_username = getenv("db_username")
db_password= getenv("db_password")

auth = (db_username, db_password)
driver = None

try:
    driver = GraphDatabase.driver(uri=db_uri, auth=auth)
    # The embedder and llm are likely not needed in this script if its sole purpose is data loading
    # embedder = OllamaEmbeddings(model="nomic-embed-text")
    # llm = OllamaLLM(model_name="nomic-embed-text")
    print("Neo4j driver initialized.")
except Exception as e:
    print(f"Failed to initialize Neo4j driver: {e}")
    # It's crucial to exit or handle this error, as the rest of the script relies on the driver
    exit(1) # Exit if driver can't be created
# --- End of setup code ---


#main function to load SDOs
def load_sdos(path):
    with open(path) as f:
        stix_json_data = json.load(f)

    stix_objects = [obj for obj in stix_json_data["objects"] if obj["type"] not in ("relationship", "x-mitre-collection")]

    for stix_object in stix_objects:

        label = to_pascal_case(stix_object["type"])
        object_properties = get_stix_properties_dict(stix_object)

        query = f"""
            MERGE (x:SDO:{label} {{id: "{stix_object["id"]}"}})
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


def load_stix_to_neo4j(path: str):
    #results = validate_file(path) # Uncomment if you want to validate STIX files
    #print_results(results)        # Uncomment if you want to print validation results
    print(f"Loading SDOs from {path}...")
    load_sdos(path)
    print(f"Loading SROs from {path}...")
    load_sros(path)
    print(f"Loading embedded relationships from {path}...")
    load_embedded_relationships(path)
    print(f"Finished loading data from {path}.")

try:
     with driver.session(bookmarks=None) as session:
        print(f"Connecting to default Neo4j database.")
        load_stix_to_neo4j("ics-attack-17.1.json")

     #with driver.session(database=db_name) as session:
        #print(f"Connecting to Neo4j database: {db_name}")
        #load_stix_to_neo4j("ics-attack-17.1.json")
        #load_stix_to_neo4j("attack-stix-data/mobile-attack-17.1.json")
        #load_stix_to_neo4j("attack-stix-data/enterprise-attack-17.1.json")
except Exception as e:
    print(f"An error occurred during data loading: {e}")
finally:
    if driver:
        print("Closing Neo4j driver...")
        driver.close()
        print("Neo4j driver closed.")
