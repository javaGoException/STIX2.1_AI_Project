from neo4j import GraphDatabase
from neo4j_graphrag.llm import OllamaLLM
from neo4j_graphrag.embeddings import OllamaEmbeddings
from neo4j_graphrag.retrievers import Text2CypherRetriever, VectorRetriever
import csv, time
import ast

# Insert your Neo4j instance URL and credentials
URI = "neo4j+s://6224f1f3.databases.neo4j.io"
AUTH = ("neo4j", "DBy7vuJuvsbib8F3FRhIXzIFu5vsgPxs31gJoANwMlo")

driver = GraphDatabase.driver(URI, auth=AUTH)

# ollama run ollama run gemma3:27b-it-q8_0
llm = OllamaLLM(model_name="gemma3:27b-it-qat")

# ollama run rjmalagon/gte-qwen2-7b-instruct:f16
embedder = OllamaEmbeddings(model="rjmalagon/gte-qwen2-7b-instruct:f16")


def query_vector_sim_txt2cypher_approach(
    query: str, a: str, b: str, c: str, d: str, vector_retrieval_top_k: int = 10
) -> str:

    query = f"""{query}? {a}, {b}, {c} or {d}?"""
    vector_retriever = VectorRetriever(driver, "SDOs", embedder)
    result = vector_retriever.search(query_text=query, top_k=vector_retrieval_top_k)

    nodes_str = ""
    for item in result.items:
        if not item.metadata:
            continue

        content = ast.literal_eval(item.content)

        nodes_str += f"{item.metadata["nodeLabels"][1]} {{name: '{content["name"]}'}}\n"

    SCHEMA = """Node properties:
    attack_pattern {name: STRING, description: STRING}
    campaign {name: STRING, description: STRING}
    course_of_action {name: STRING, description: STRING}
    identity {name: STRING, description: STRING}
    intrusion_set {name: STRING, description: STRING}
    malware {name: STRING, description: STRING}
    tool {name: STRING, description: STRING}
    x_mitre_data_source {name: STRING, description: STRING}
    x_mitre_data_component {name: STRING, description: STRING}
    x_mitre_tactic {name: STRING, description: STRING}
    Relationship properties:
    attributed_to {}
    component_of {}
    contains_technique {}
    detects {description: STRING}
    mitigates {description: STRING}
    subtechnique_of {}
    uses {description: STRING}
    The relationships:
    (:course_of_action)-[:mitigates]->(:attack_pattern) Mitigation mitigating technique.
    (:malware)-[:uses]->(:attack_pattern) Malware using a technique.
    (:tool)-[:uses]->(:attack_pattern) Tool using a technique.
    (:x_mitre_tactic)-[:contains_technique]->(:attack_pattern) Tactic containing a technique.
    (:attack_pattern)-[:subtechnique_of]->(:attack_pattern) Sub-technique of a technique. 
    (:x_mitre_data_component)-[:component_of]->(:x_mitre_data_source) Data component being part of a data source.
    (:x_mitre_data_component)-[:detects]->(:attack_pattern) Data component detecting a technique.
    (:intrusion_set)-[:uses]->(:malware) Group using a malware.
    (:intrusion_set)-[:uses]->(:tool) Group using a tool.
    (:intrusion_set)-[:uses]->(:attack_pattern) Group using a technique.
    (:campaign)-[:attributed_to]->(:intrusion_set) Campaign attributed to a group.
    (:campaign)-[:uses]->(:tool) Campaign using a tool.
    (:campaign)-[:uses]->(:attack_pattern) Campaign using a technique.
    (:campaign)-[:uses]->(:malware) Campaign using a malware."""

    PROMPT = """Task: Generate a Cypher statement for querying a Neo4j graph database from a user input.

    Example:
    How to prevent Phishing attacks?
    MATCH (co:course_of_action)-[m:mitigates]->(ap:attack_pattern)
    WHERE ap.name = 'Phishing'
    RETURN co.name, co.description, m.description
    LIMIT 10

    Schema:
    {schema}

    Retrieved Nodes:
    {nodes}
    Input:
    {query_text}

    Do not use any properties or relationships not included in the schema.
    Retrieved Nodes have been retrieved from the graph in advance by using Vector Similarity. You may use them, but you do not have to. 
    Do not include triple backticks ``` or any additional text except the generated Cypher statement in your response.

    Cypher query:
    """

    txt2cypher_retriever = Text2CypherRetriever(
        driver=driver, llm=llm, neo4j_schema=SCHEMA, custom_prompt=PROMPT
    )

    result = txt2cypher_retriever.search(
        query_text=query,
        prompt_params={"schema": SCHEMA, "nodes": nodes_str},
    )

    context_str = ""
    for item in result.items:
        context_str += f"{item.content}\n"

    cypher = ""
    if result.metadata:
        cypher = result.metadata.get("cypher")

    SYSTEM_INSTRUCTION = "Answer the user question using the provided context, which has been retrieved from a graph using the provided Cypher query. Answer only with one char A, B, C or D. Do not explain."
    final_prompt = f"""Cypher Query:
{cypher}
Context:
{context_str}
Question:
{query}

Possible answers:
A - {a}
B - {b}
C - {c}
D - {d}

Answer:
"""

    print(final_prompt)

    result = str(
        llm.invoke(input=final_prompt, system_instruction=SYSTEM_INSTRUCTION).content
    )
    print(result)
    return result


with open(
    "../AttackSeq-Technique.csv", mode="r", newline="", encoding="utf-8"
) as infile, open("approach4.csv", mode="w", newline="", encoding="utf-8") as outfile:

    reader = csv.DictReader(infile)
    fieldnames = ["Question ID", "Answer", "Latency"]
    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
    writer.writeheader()

    for row in reader:
        question_id = row.get("Question ID", "")
        question_text = row.get("Question", "")

        a = row.get("A", "")
        b = row.get("B", "")
        c = row.get("C", "")
        d = row.get("D", "")

        print(f"---------- {question_id} ----------")

        try:
            start_time = time.time()
            answer = query_vector_sim_txt2cypher_approach(question_text, a, b, c, d)
            latency = round(time.time() - start_time, 4)

            writer.writerow(
                {"Question ID": question_id, "Answer": answer, "Latency": latency}
            )
        except Exception as e:
            print(f"Error processing {question_id}: {e}")
