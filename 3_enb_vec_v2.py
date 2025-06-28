import json
import ast
import os
from os import getenv
from dotenv import load_dotenv
from neo4j import GraphDatabase

from neo4j_graphrag.embeddings import OllamaEmbeddings
from neo4j_graphrag.indexes import upsert_vectors
from neo4j_graphrag.types import EntityType


# --- Start of setup code ---
load_dotenv(".env")
db_uri = getenv("db_uri")
db_name = getenv("db_name")
db_username = getenv("db_username")
db_password = getenv("db_password")

auth = (db_username, db_password)
driver = None # Initialize driver to None for proper error handling

try:
    # Initialize the standard Neo4j driver
    driver = GraphDatabase.driver(uri=db_uri, auth=auth)
    print("Neo4j driver initialized.")

    # Initialize the embedder
    embedder = OllamaEmbeddings(model="nomic-embed-text")
    print("OllamaEmbeddings initialized.")

except Exception as e:
    print(f"Failed to initialize Neo4j driver or Embedder: {e}")
    exit(1) # Exit if essential components can't be created
# --- End of setup code ---

# Ensure the driver is closed even if errors occur during the main logic
try:
    with driver.session(bookmarks=None) as session: # Or driver.session(database=db_name) if your Neo4j version and setup requires it
        print(f"Connecting to default Neo4j database.")

        result = session.run("""
        MATCH (n:SDO)
        WHERE n.name IS NOT NULL AND n.description IS NOT NULL
        OPTIONAL MATCH (n)-[r]->(m)
        RETURN n, collect({type: type(r), target: m.name}) AS relationships
        """)

        for record in result:
            node = record["n"]
            relationships = record["relationships"]

            base_text = f"{node['name']}. {node['description']}"

            if relationships:
                # Filter out relationships where target is None (from OPTIONAL MATCH)
                rel_text = ". ".join(
                    [f"Related to {rel['target']} via {rel['type']}" for rel in relationships if rel.get("target")]
                )
                full_text = f"{base_text}. {rel_text}"
            else:
                full_text = base_text

            stix_id = node["id"]
            vector = embedder.embed_query(full_text)

            print(f"Upserting vector for node: {stix_id}")
            upsert_vectors(
                driver, # Pass the standard Neo4j driver object here
                ids=[stix_id],
                embedding_property="embedding",
                embeddings=[vector],
                entity_type=EntityType.NODE,
                #neo4j_database=db_name # This parameter is correct
            )
        print("Vector embeddings generation and upsert completed.")

except Exception as e:
    print(f"An error occurred during vector generation/upsert: {e}")
finally:
    if driver:
        print("Closing Neo4j driver...")
        driver.close()
        print("Neo4j driver closed.")
