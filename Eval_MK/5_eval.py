import json
import os
import re
from os import getenv
from dotenv import load_dotenv
from neo4j import GraphDatabase
from neo4j_graphrag.embeddings import OllamaEmbeddings
from neo4j_graphrag.retrievers import VectorRetriever
from neo4j_graphrag.llm import OllamaLLM

# --- Initialisierung ---
load_dotenv(".env")
db_uri = getenv("db_uri")
db_name = getenv("db_name")
db_username = getenv("db_username")
db_password = getenv("db_password")

auth = (db_username, db_password)
try:
    driver = GraphDatabase.driver(uri=db_uri, auth=auth)
    driver.verify_connectivity()
    print("Verbindung zu Neo4j erfolgreich hergestellt.")
except Exception as e:
    print(f"Fehler bei der Verbindung zu Neo4j: {e}")
    exit()

# Initialisiere Modelle
embedder = OllamaEmbeddings(model="nomic-embed-text")
llm = OllamaLLM(model_name="deepseek-r1:1.5b")
retriever = VectorRetriever(driver, "nodes", embedder, neo4j_database=db_name)


# --- Hilfsfunktionen für RAG ---

def get_neighborhood(driver, node_id):
    # direkte Nachbarn holen
    with (driver.session(database=db_name) as session):
        result = session.run("""
            MATCH (n)-[r]-(m)
            WHERE elementId(n) = $id OR n.id = $id
            RETURN DISTINCT m, type(r) AS rel_type
        """, id=node_id)
        return [(record["m"], record["rel_type"]) for record in result]


def build_question_context(main_node, neighbors):
    #LLM Kontext-String generieren
    parts = []
    main_node_desc = main_node.get('description', 'Keine Beschreibung verfügbar.')
    parts.append(
        f"Bester Treffer der Suche:\n\"{main_node.get('name')}\" vom Typ \"{main_node.get('type')}\": {main_node_desc}")

    if neighbors:
        parts.append("\nNachbarn:")
        for neighbor, rel_type in neighbors:
            neighbor_desc = neighbor.get('description', 'Keine Beschreibung verfügbar.')
            parts.append(
                f"Verbunden über \"{rel_type}\" mit \"{neighbor.get('name')}\" vom Typ \"{neighbor.get('type')}\": {neighbor_desc}")

    return "\n".join(parts)


def run_rag_query(query_text: str) -> str:
    # 1. & 2. Ähnlichkeitssuche und Nachbarschaftsabruf
    try:
        search_result = retriever.search(query_text=query_text, top_k=1)
        if not search_result.items:
            print("Keine relevanten Knoten im Graphen gefunden.")
            # Fallback-Idee?: ohne Kontext an das LLM senden + Hinweis
            question_context = "Kein Kontext gefunden. Beantworte die Frage basierend auf deinem allgemeinen Wissen. Gebe bitte aus das du keinen weiteren Kontext dazu bekommen hast."
        else:
            main_item_dict = search_result.items[0].metadata
            neighbors = get_neighborhood(driver, main_item_dict["id"])
            question_context = build_question_context(main_item_dict, neighbors)
    except Exception as e:
        print(f"Fehler bei der RAG-Abfrage: {e}")
        return "Fehler bei der Abfrage."

    # 3. LLM-Anfrage mit Kontext
    try:
        response = llm.invoke(
            input=query_text,
            system_instruction=question_context
        )
        return response.content
    except Exception as e:
        print(f"Fehler bei der LLM-Anfrage: {e}")
        return "Fehler bei der LLM-Antwort."


# --- Benchmark ---

def load_benchmark_data(file_path: str):
    # JSON Daten laden
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"Fehler: Die Datei {file_path} wurde nicht gefunden.")
        return None
    except json.JSONDecodeError:
        print(f"Fehler: Die Datei {file_path} ist keine gültige JSON-Datei.")
        return None


def parse_llm_answer(response: str, choices: list) -> str:
    # extrahieren der Antwort aus LLM Antwort
    response_lower = response.lower()

    # Prüfe auf "Final Answer: X"
    match = re.search(r"final answer:.*?([a-d])", response_lower)
    if match:
        return match.group(1).upper()

    # Prüfe auf explizite Nennung wie "Antwort ist B" oder "Choice B"
    for i, choice in enumerate(choices):
        letter = chr(ord('A') + i)
        if f"choice {letter.lower()}" in response_lower or f"antwort {letter.lower()}" in response_lower or f"option {letter.lower()}" in response_lower:
            return letter

    # Fallback für Ja/Nein Fragen
    if "yes" in response_lower and "no" not in response_lower:
        return "Yes"
    if "no" in response_lower and "yes" not in response_lower:
        return "No"

    # Wenn nichts gefunden wird, gib eine leere Zeichenkette zurück
    return ""


def evaluate_task(task_name: str, benchmark_data: list):
    #Evaluierung der Aufgabe
    correct_predictions = 0
    total_questions = len(benchmark_data)

    print(f"\n--- Starte Evaluierung für: {task_name} ---")

    for i, item in enumerate(benchmark_data):
        question = item['question']
        choices = item['choices']
        correct_answer_label = item['answer']

        # Erstelle den vollständigen Prompt-Text mit Antwortmöglichkeiten
        full_query = f"{question}\n"
        for letter, choice_text in choices.items():
            full_query += f"{letter}) {choice_text}\n"
        full_query += "Bitte gib deine finale Antwort im Format 'Final Answer: <BUCHSTABE>' an."

        # Führe die RAG-Abfrage durch
        llm_response = run_rag_query(full_query)

        # Parse die Antwort
        predicted_answer_label = parse_llm_answer(llm_response, list(choices.keys()))

        if predicted_answer_label == correct_answer_label:
            correct_predictions += 1
            print(
                f"Frage {i + 1}/{total_questions}: Korrekt! (Erwartet: {correct_answer_label}, Erhalten: {predicted_answer_label})")
        else:
            print(
                f"Frage {i + 1}/{total_questions}: Falsch. (Erwartet: {correct_answer_label}, Erhalten: {predicted_answer_label})")
            # print(f"  LLM-Antwort: {llm_response[:200]}...") # DEB

    accuracy = (correct_predictions / total_questions) * 100 if total_questions > 0 else 0
    print(f"\n--- Ergebnis für {task_name} ---")
    print(f"Korrekte Antworten: {correct_predictions} von {total_questions}")
    print(f"Genauigkeit (Accuracy): {accuracy:.2f}%")

    return accuracy

def main():
    #Bench-Pfad
    benchmark_base_path = './AttackSeqBench/dataset'

    tasks = {
        "AttackSeq-Tactic": "attackseq-tactic.json",
        "AttackSeq-Technique": "attackseq-technique.json",
        "AttackSeq-Procedure": "attackseq-procedure.json",
    }

    results = {}

    for task_name, file_name in tasks.items():
        file_path = os.path.join(benchmark_base_path, file_name)
        data = load_benchmark_data(file_path)
        if data:
            accuracy = evaluate_task(task_name, data)
            results[task_name] = accuracy

    print("\n--- Gesamtergebnis der Evaluierung ---")
    for task_name, accuracy in results.items():
        print(f"{task_name}: {accuracy:.2f}% Genauigkeit")

    driver.close()
    print("\nEvaluierung abgeschlossen und Verbindung zu Neo4j geschlossen.")

if __name__ == "__main__":
    main()
