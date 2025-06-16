import json
import ast
import os
from os import getenv
from stix2validator import validate_file, print_results
from dotenv import load_dotenv
from neo4j import GraphDatabase

from neo4j_graphrag.embeddings import OllamaEmbeddings
from neo4j_graphrag.indexes import create_vector_index
from neo4j_graphrag.indexes import upsert_vectors
from neo4j_graphrag.types import EntityType
from neo4j_graphrag.retrievers import VectorRetriever
from neo4j_graphrag.llm import OllamaLLM


load_dotenv(".env")
db_uri = getenv("db_uri")
db_name = getenv("db_name")
db_username = getenv("db_username")
db_password= getenv("db_password")

auth = (db_username, db_password)
driver = None # Initialize driver to None

try:
    driver = GraphDatabase.driver(uri=db_uri, auth=auth)
    embedder = OllamaEmbeddings(model="nomic-embed-text")
    llm = OllamaLLM(model_name="nomic-embed-text")

    # Your main application logic goes here
    # Example:
    # with driver.session() as session:
    #     session.run("MATCH (n) RETURN n LIMIT 1")

    print("Application finished successfully.")

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    if driver:
        print("Closing Neo4j driver...")
        driver.close() # Ensure the driver is closed
        print("Neo4j driver closed.")
