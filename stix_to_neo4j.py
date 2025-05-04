import json
from os import getenv
from stix2validator import validate_file, print_results
from dotenv import load_dotenv
from neo4j import GraphDatabase, RoutingControl


load_dotenv(".env")
db_uri = getenv("db_uri")
db_name = getenv("db_name")
db_username = getenv("db_username")
db_password= getenv("db_password")
auth = (db_username, db_password)
driver = GraphDatabase.driver(uri=db_uri, auth=auth)


#main function to load SDOs
def load_sdos_to_neo4j(path):
    with open(path) as f:
        stix_json_data = json.load(f)

    for stix_object in stix_json_data["objects"]:

        if stix_object["type"] == "attack-pattern":
            load_sdo_common_properties("AttackPattern", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (a:AttackPattern {id: $id})
                SET a.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "campaign":
            load_sdo_common_properties("Campaign", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (c:Campaign {id: $id})
                SET c.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "course-of-action":
            load_sdo_common_properties("CourseOfAction", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (c:CourseOfAction {id: $id})
                SET c.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "identity":
            load_sdo_common_properties("Identity", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (i:Identity {id: $id})
                SET i.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "infrastructure":
            load_sdo_common_properties("Infrastructure", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (i:Infrastructure {id: $id})
                SET i.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "intrusion-set":
            load_sdo_common_properties("IntrusionSet", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (i:IntrusionSet {id: $id})
                SET i.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "location":
            load_sdo_common_properties("Location", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

        if stix_object["type"] == "malware":
            load_sdo_common_properties("Malware", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

        if stix_object["type"] == "malware-analysis":
            load_sdo_common_properties("MalwareAnalysis", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

        if stix_object["type"] == "note":
            load_sdo_common_properties("Note", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])
            query = """
                MERGE (n:Note {id: $id})
                SET n.content = $content
                """
            session.run(
                query,
                id=stix_object["id"],
                content=stix_object["content"]
            )

        if stix_object["type"] == "observed-data":
            load_sdo_common_properties("ObservedData", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (o:ObservedData {id: $id})
                SET o.first_observed = datetime($first_observed),
                    o.last_observed = datetime($last_observed),
                    o.number_observed = $number_observed
                """
            session.run(
                query,
                id=stix_object["id"],
                first_observed=stix_object["first_observed"],
                last_observed=stix_object["last_observed"],
                number_observed=stix_object["$number_observed"]
            )

        if stix_object["type"] == "report":
            load_sdo_common_properties("Report", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (r:Report {id: $id})
                SET r.name = $name,
                    r.published  = datetime($published)
                """
            session.run(
                query,
                id=stix_object["id"],
                name=stix_object["name"],
                published=stix_object["published"]
            )

        if stix_object["type"] == "threat-actor":
            load_sdo_common_properties("ThreatActor", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (t:ThreatActor {id: $id})
                SET t.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                name=stix_object["name"],
            )

        if stix_object["type"] == "tool":
            load_sdo_common_properties("Tool", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (t:Tool {id: $id})
                SET t.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                name=stix_object["name"],
            )

        if stix_object["type"] == "vulnerability":
            load_sdo_common_properties("Vulnerability", stix_object["id"], stix_object["type"], stix_object["spec_version"],
                                       stix_object["created"], stix_object["modified"])

            query = """
                MERGE (v:Vulnerability {id: $id})
                SET v.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                name=stix_object["name"],
            )


#main function to load SROs
def load_sros_to_neo4j(path):
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


#used by the load_sdos_to_neo4j()
def load_sdo_common_properties(label, stix_id, stix_type, stix_spec_version, stix_created, stix_modified):
    query = f"""
        MERGE (x:{label} {{id: $id}})
        SET x.type = $type,
            x.spec_version = $spec_version,
            x.created = datetime($created),
            x.modified = datetime($modified)
        """
    session.run(
        query,
        id=stix_id,
        type=stix_type,
        spec_version=stix_spec_version,
        created=stix_created,
        modified=stix_modified
    )


def to_pascal_case(input_string):
  words = input_string.split('-')
  pascal_case_string = "".join(word.capitalize() for word in words)

  return pascal_case_string


with (driver.session(database=db_name) as session):

    def load_ics(path: str):
        # results = validate_file(path)
        # print_results(results)
        load_sdos_to_neo4j(path)
        load_sros_to_neo4j(path)

    def load_mobile(path: str):
        # results = validate_file(path)
        # print_results(results)
        load_sdos_to_neo4j(path)
        load_sros_to_neo4j(path)

    def load_enterprise(path: str):
        # results = validate_file(path)
        # print_results(results)
        load_sdos_to_neo4j(path)
        load_sros_to_neo4j(path)

    load_ics("attack-stix-data/ics-attack-17.0.json")
    load_mobile("attack-stix-data/mobile-attack-17.0.json")
    load_enterprise("attack-stix-data/enterprise-attack-17.0.json")

driver.close()