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


def to_pascal_case(input_string):
  # Remove the "x-" prefix if it exists
  if input_string.startswith("x-"):
    input_string = input_string[2:]

  # Split the string by hyphens
  words = input_string.split('-')

  # Capitalize the first letter of each word and join them
  pascal_case_string = "".join(word.capitalize() for word in words)

  return pascal_case_string

def load_json_to_neo4j(path):
    with open(path) as f:
        stix_json_data = json.load(f)

    for stix_object in stix_json_data["objects"]:

        if stix_object["type"] == "attack-pattern":
            query = """
                MERGE (a:AttackPattern {id: $id})
                SET a.type = $type,
                    a.spec_version = $spec_version,
                    a.created = datetime($created),
                    a.modified = datetime($modified),
                    a.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "campaign":
            query = """
                MERGE (c:Campaign {id: $id})
                SET c.type = $type,
                    c.spec_version = $spec_version,
                    c.created = datetime($created),
                    c.modified = datetime($modified),
                    c.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "course-of-action":
            query = """
                MERGE (c:CourseOfAction {id: $id})
                SET c.type = $type,
                    c.spec_version = $spec_version,
                    c.created = datetime($created),
                    c.modified = datetime($modified),
                    c.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "identity":
            query = """
                MERGE (i:Identity {id: $id})
                SET i.type = $type,
                    i.spec_version = $spec_version,
                    i.created = datetime($created),
                    i.modified = datetime($modified),
                    i.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "infrastructure":
            query = """
                MERGE (i:Infrastructure {id: $id})
                SET i.type = $type,
                    i.spec_version = $spec_version,
                    i.created = datetime($created),
                    i.modified = datetime($modified),
                    i.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "intrusion-set":
            query = """
                MERGE (i:IntrusionSet {id: $id})
                SET i.type = $type,
                    i.spec_version = $spec_version,
                    i.created = datetime($created),
                    i.modified = datetime($modified),
                    i.name = $name
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
                name=stix_object["name"]
            )

        if stix_object["type"] == "location":
            query = """
                MERGE (l:Location {id: $id})
                SET l.type = $type,
                    l.spec_version = $spec_version,
                    l.created = datetime($created),
                    l.modified = datetime($modified),
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
            )

        if stix_object["type"] == "malware":
            query = """
                MERGE (m:Malware {id: $id})
                SET m.type = $type,
                    m.spec_version = $spec_version,
                    m.created = datetime($created),
                    m.modified = datetime($modified)
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
            )

        if stix_object["type"] == "malware-analysis":
            query = """
                MERGE (m:MalwareAnalysis {id: $id})
                SET m.type = $type,
                    m.spec_version = $spec_version,
                    m.created = datetime($created),
                    m.modified = datetime($modified)
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
            )

        if stix_object["type"] == "note":
            query = """
                MERGE (n:Note {id: $id})
                SET n.type = $type,
                    n.spec_version = $spec_version,
                    n.created = datetime($created),
                    n.modified = datetime($modified),
                    n.content = $content
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
                content=stix_object["content"],
            )

        if stix_object["type"] == "observed-data":
            query = """
                MERGE (o:ObservedData {id: $id})
                SET o.type = $type,
                    o.spec_version = $spec_version,
                    o.created = datetime($created),
                    o.modified = datetime($modified),
                    o.first_observed = datetime($first_observed),
                    o.last_observed = datetime($last_observed),
                    o.number_observed = $number_observed
                """
            session.run(
                query,
                id=stix_object["id"],
                type=stix_object["type"],
                spec_version=stix_object["spec_version"],
                created=stix_object["created"],
                modified=stix_object["modified"],
                first_observed=stix_object["first_observed"],
                last_observed=stix_object["last_observed"],
                number_observed=stix_object["$number_observed"]
            )

            if stix_object["type"] == "report":
                query = """
                    MERGE (r:report {id: $id})
                    SET r.type = $type,
                        r.spec_version = $spec_version,
                        r.created = datetime($created),
                        r.modified = datetime($modified),
                        r.name = $name,
                        r.published  = datetime($published)
                    """
                session.run(
                    query,
                    id=stix_object["id"],
                    type=stix_object["type"],
                    spec_version=stix_object["spec_version"],
                    created=stix_object["created"],
                    modified=stix_object["modified"],
                    name=stix_object["name"],
                    published=stix_object["published"]
                )

            if stix_object["type"] == "threat-actor":
                query = """
                    MERGE (t:ThreatActor {id: $id})
                    SET t.type = $type,
                        t.spec_version = $spec_version,
                        t.created = datetime($created),
                        t.modified = datetime($modified),
                        t.name = $name
                    """
                session.run(
                    query,
                    id=stix_object["id"],
                    type=stix_object["type"],
                    spec_version=stix_object["spec_version"],
                    created=stix_object["created"],
                    modified=stix_object["modified"],
                    name=stix_object["name"],
                )

            if stix_object["type"] == "tool":
                query = """
                    MERGE (t:Tool {id: $id})
                    SET t.type = $type,
                        t.spec_version = $spec_version,
                        t.created = datetime($created),
                        t.modified = datetime($modified),
                        t.name = $name
                    """
                session.run(
                    query,
                    id=stix_object["id"],
                    type=stix_object["type"],
                    spec_version=stix_object["spec_version"],
                    created=stix_object["created"],
                    modified=stix_object["modified"],
                    name=stix_object["name"],
                )

            if stix_object["type"] == "vulnerability":
                query = """
                    MERGE (v:Vulnerability {id: $id})
                    SET v.type = $type,
                        v.spec_version = $spec_version,
                        v.created = datetime($created),
                        v.modified = datetime($modified),
                        v.name = $name
                    """
                session.run(
                    query,
                    id=stix_object["id"],
                    type=stix_object["type"],
                    spec_version=stix_object["spec_version"],
                    created=stix_object["created"],
                    modified=stix_object["modified"],
                    name=stix_object["name"],
                )


with (driver.session(database=db_name) as session):

    def load_ics(path: str):
        # results = validate_file(path)
        # print_results(results)
        load_json_to_neo4j(path)

    def load_mobile(path: str):
        # results = validate_file(path)
        # print_results(results)
        load_json_to_neo4j(path)

    def load_enterprise(path: str):
        # results = validate_file(path)
        # print_results(results)
        load_json_to_neo4j(path)

    load_ics("attack-stix-data/ics-attack-17.0.json")
    load_mobile("attack-stix-data/mobile-attack-17.0.json")
    load_enterprise("attack-stix-data/enterprise-attack-17.0.json")

driver.close()