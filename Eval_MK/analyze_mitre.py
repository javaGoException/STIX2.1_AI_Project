import pandas as pd
import re

def calculate_metrics(df_path):
    """
    Berechnet verschiedene Metriken für verschiedene LLM-Ansätze aus einer CSV-Datei.

    Args:
        df_path (str): Der Pfad zur CSV-Datei.
                       Die CSV-Datei sollte durch Kommas (,) getrennt sein.
    """
    try:
        df = pd.read_csv(df_path, sep=',')
    except FileNotFoundError:
        print(f"Fehler: Datei nicht gefunden unter '{df_path}'. Bitte den korrekten Pfad überprüfen.")
        return None
    except Exception as e:
        print(f"Fehler beim Lesen der CSV-Datei: {e}")
        return None

    for col in df.columns:
        if 'Correctness' in col:
            # Convert 'Correctness' values to 0/1, handling potential non-string values gracefully
            df[col] = df[col].apply(lambda x: 1 if str(x).strip().lower() == 'correct' else 0)

    results = {}

    approaches = {
        "QO": {
            "answer_col": "Answer LLM (QO)", "correctness_col": "Correctness (QO)", "duration_col": "Duration (QO)",
            "length_thinking_col": "Length Thinking (QO)", "length_answer_col": "Length Answer (QO)",
            "llm_input_col": "LLM Input (QO)"
        },
        "RAG": {
            "answer_col": "Answer LLM (RAG)", "correctness_col": "Correctness (RAG)", "duration_col": "Duration (RAG)",
            "length_thinking_col": "Length Thinking (RAG)", "length_answer_col": "Length Answer (RAG)",
            "main_retrieved_node_col": "Main Retrieved Node Name (RAG)", "num_retrieved_neighbors_col": "Num Retrieved Neighbors (RAG)",
            "llm_input_col": "LLM Input (RAG)"
        },
        "Choices": {
            "answer_col": "Answer LLM (Choices)", "correctness_col": "Correctness (Choices)", "duration_col": "Duration (Choices)",
            "length_thinking_col": "Length Thinking (Choices)", "length_answer_col": "Length Answer (Choices)",
            "main_retrieved_node_col": "Main Retrieved Node Name (Choices)", "num_retrieved_neighbors_col": "Num Retrieved Neighbors (Choices)",
            "llm_input_col": "LLM Input (Choices)", "llm_choices_col": "LLM Choices (Choices)"
        },
        "Choices No RAG": {
            "answer_col": "Answer LLM (Choices No RAG)", "correctness_col": "Correctness (Choices No RAG)", "duration_col": "Duration (Choices No RAG)",
            "length_thinking_col": "Length Thinking (Choices No RAG)", "length_answer_col": "Length Answer (Choices No RAG)",
            "llm_input_col": "LLM Input (Choices No RAG)", "llm_choices_col": "LLM Choices (Choices No RAG)"
        }
    }

    def calculate_f1_for_texts(ground_truth, answer):
        # Ensure inputs are strings and handle NaN
        ground_truth = str(ground_truth) if pd.notna(ground_truth) else ""
        answer = str(answer) if pd.notna(answer) else ""

        gt_tokens = set(re.findall(r'\b\w+\b', ground_truth.lower()))
        ans_tokens = set(re.findall(r'\b\w+\b', answer.lower()))

        common_tokens = len(gt_tokens.intersection(ans_tokens))
        if common_tokens == 0:
            return 0.0

        precision = common_tokens / len(ans_tokens) if len(ans_tokens) > 0 else 0.0
        recall = common_tokens / len(gt_tokens) if len(gt_tokens) > 0 else 0.0

        if precision + recall == 0:
            return 0.0
        f1 = 2 * (precision * recall) / (precision + recall)
        return f1


    for approach_name, cols in approaches.items():
        print(f"\n--- Metriken für {approach_name} ---") # Keep detailed printout for individual approach
        current_results = {}

        # Check if core columns exist for the current approach
        if cols["correctness_col"] not in df.columns or cols["answer_col"] not in df.columns:
            print(f"Warnung: Spalten '{cols['correctness_col']}' oder '{cols['answer_col']}' nicht für '{approach_name}' gefunden. Überspringe Metrikberechnung.")
            results[approach_name] = current_results
            continue

        # Filter rows where core answer/correctness columns are not missing
        relevant_rows_mask = df[cols["correctness_col"]].notna() & df[cols["answer_col"]].notna()
        df_filtered = df[relevant_rows_mask].copy() # Use .copy() to avoid SettingWithCopyWarning

        if df_filtered.empty:
            print(f"Keine relevanten Daten für {approach_name} gefunden. Überspringe Metrikberechnung.")
            results[approach_name] = current_results
            continue

        # 1. Accuracy
        correct_answers = df_filtered[cols["correctness_col"]].sum()
        total_questions = df_filtered[cols["correctness_col"]].count()
        accuracy = correct_answers / total_questions if total_questions > 0 else 0
        current_results["Accuracy"] = accuracy
        print(f"Genauigkeit (Accuracy): {accuracy:.4f}")

        # 2. EM and F1 Score
        em_score = accuracy
        current_results["EM Score"] = em_score
        print(f"Exakter Treffer (EM) Score: {em_score:.4f}")

        f1_scores_list = []
        if 'Ground Truth' in df_filtered.columns:
            for _, row in df_filtered.iterrows():
                f1_scores_list.append(calculate_f1_for_texts(row['Ground Truth'], row[cols["answer_col"]]))
        else:
            print(f"Warnung: Spalte 'Ground Truth' nicht gefunden. F1-Score kann nicht berechnet werden.")
            f1_scores_list = [] # Ensure it's empty if Ground Truth is missing

        avg_f1_score = sum(f1_scores_list) / len(f1_scores_list) if len(f1_scores_list) > 0 else 0
        current_results["Durchschnittlicher F1 Score"] = avg_f1_score
        print(f"Durchschnittlicher F1 Score (Textvergleich): {avg_f1_score:.4f}")

        # 3. Antwortlänge im Vergleich zur Korrektheit
        df_filtered.loc[:, 'Length Answer Temp'] = df_filtered[cols["answer_col"]].astype(str).apply(len)
        correct_answers_df = df_filtered[df_filtered[cols["correctness_col"]] == 1]
        incorrect_answers_df = df_filtered[df_filtered[cols["correctness_col"]] == 0]

        avg_len_correct = correct_answers_df['Length Answer Temp'].mean()
        avg_len_incorrect = incorrect_answers_df['Length Answer Temp'].mean()
        current_results["Durchschnittliche Antwortlänge (Korrekt)"] = avg_len_correct
        current_results["Durchschnittliche Antwortlänge (Inkorrekt)"] = avg_len_incorrect
        print(f"Durchschnittliche Antwortlänge (Korrekt): {avg_len_correct:.2f}")
        print(f"Durchschnittliche Antwortlänge (Inkorrekt): {avg_len_incorrect:.2f}")
        df_filtered = df_filtered.drop(columns=['Length Answer Temp']) # Clean up temp column

        # 4. Num Retrieved Neighbors im Vergleich zur Korrektheit (nur für RAG und Choices)
        if "num_retrieved_neighbors_col" in cols and cols["num_retrieved_neighbors_col"] in df_filtered.columns:
            df_filtered.loc[:, cols["num_retrieved_neighbors_col"]] = pd.to_numeric(df_filtered[cols["num_retrieved_neighbors_col"]], errors='coerce')
            avg_num_neighbors_correct = correct_answers_df[cols["num_retrieved_neighbors_col"]].mean()
            avg_num_neighbors_incorrect = incorrect_answers_df[cols["num_retrieved_neighbors_col"]].mean()
            current_results["Durchschnittliche Anzahl abgerufener Nachbarn (Korrekt)"] = avg_num_neighbors_correct
            current_results["Durchschnittliche Anzahl abgerufener Nachbarn (Inkorrekt)"] = avg_num_neighbors_incorrect
            print(f"Durchschnittliche Anzahl abgerufener Nachbarn (Korrekt): {avg_num_neighbors_correct:.2f}")
            print(f"Durchschnittliche Anzahl abgerufener Nachbarn (Inkorrekt): {avg_num_neighbors_incorrect:.2f}")
        else:
            print("Spalte 'Num Retrieved Neighbors' nicht anwendbar oder für diesen Ansatz nicht gefunden.")

        # 5. Zeit im Vergleich zur Korrektheit
        if cols["duration_col"] in df_filtered.columns:
            df_filtered.loc[:, cols["duration_col"]] = pd.to_numeric(df_filtered[cols["duration_col"]], errors='coerce')
            avg_duration_correct = correct_answers_df[cols["duration_col"]].mean()
            avg_duration_incorrect = incorrect_answers_df[cols["duration_col"]].mean()
            current_results["Durchschnittliche Dauer (Korrekt)"] = avg_duration_correct
            current_results["Durchschnittliche Dauer (Inkorrekt)"] = avg_duration_incorrect
            print(f"Durchschnittliche Dauer (Korrekt): {avg_duration_correct:.2f} Sekunden")
            print(f"Durchschnittliche Dauer (Inkorrekt): {avg_duration_incorrect:.2f} Sekunden")
        else:
            print("Spalte 'Duration' für diesen Ansatz nicht gefunden.")

        results[approach_name] = current_results
    return results

def print_formatted_table(metrics_results):
    """
    Gibt die berechneten Metriken in einem tabellarischen Format mit vertikalen Strichen aus.
    """
    if not metrics_results:
        print("Keine Metriken zum Anzeigen vorhanden.")
        return

    display_df = pd.DataFrame.from_dict(metrics_results, orient='index')
    display_df.index.name = "Ansatz"

    # Sortiere die Spalten alphabetisch
    display_df = display_df.reindex(sorted(display_df.columns), axis=1)

    # Formatierungsfunktion für numerische Werte
    def format_value(val, decimals=4):
        if pd.isna(val):
            return ""
        return f"{val:.{decimals}f}"

    # Anwenden der Formatierung auf alle numerischen Spalten
    for col in display_df.columns:
        if pd.api.types.is_numeric_dtype(display_df[col]):
            display_df[col] = display_df[col].apply(lambda x: format_value(x, 4)) # Einheitlich 4 Dezimalstellen

    # Berechne maximale Spaltenbreiten für die Formatierung
    # +3 für " | " Trennzeichen (Padding + '|' + Padding)
    max_col_widths = {col: max(display_df[col].astype(str).apply(len).max(), len(col)) + 2 for col in display_df.columns}
    max_index_width = max(len(str(idx)) for idx in display_df.index.values) + 2 # Für den 'Ansatz' Index

    # Gesamtbreite der Tabelle für die Trennlinien
    total_width = sum(max_col_widths.values()) + max_index_width + (len(display_df.columns)) # Extra 1 for initial '|' + (num_cols * '|' )

    print("\n" + "=" * total_width)
    print("Zusammenfassende Metriken für LLM-Ansätze".center(total_width))
    print("=" * total_width)

    # Header-Zeile
    header_line = f"| {'Ansatz':<{max_index_width-2}} | " + \
                  " | ".join([f"{col:<{max_col_widths[col]-2}}" for col in display_df.columns]) + " |"
    print(header_line)
    print("|" + "-" * (total_width - 2) + "|") # Trennlinie unter dem Header

    # Datenzeilen
    for index, row in display_df.iterrows():
        row_values = [f"{str(row[col]):<{max_col_widths[col]-2}}" for col in display_df.columns]
        data_line = f"| {str(index):<{max_index_width-2}} | " + \
                    " | ".join(row_values) + " |"
        print(data_line)

    print("=" * total_width)

metrics_results = calculate_metrics('evaluation_results.csv')

if metrics_results:
    print_formatted_table(metrics_results)

"""
#-#Metrik-Spalten#-#
#Accuracy (Genauigkeit):#

Definition: einfachste Maß, Berechnung =  Anzahl korrekter Antworten/ Gesamtzahl der Fragen
Aussagekraft: richtige Fragen 

#Durchschnittliche Antwortlänge (Inkorrekt) / (Korrekt):#

Definition: Durchschnitt der Zeichenlänge der vom LLM generierten Antworten, getrennt nach inkorrekt / korrekt 
Aussagekraft: LLM bei korrekten Antworten tendenziell prägnanter oder ausführlicher? 
Extrem lange inkorrekte Antworten --> "Halluzinationen" oder irrelevante Dinge?

#Durchschnittliche Anzahl abgerufener Nachbarn (Inkorrekt) / (Korrekt):#

Definition: getrennt nach korrekten und inkorrekten Antworten. (nur RAG oder Choices) 
Aussagekraft: höhere oder niedrigere Anzahl abgerufener Knoten besser oder schlechter für das Ergebnis

#Durchschnittliche Dauer (Inkorrekt) / (Korrekt):#

Definition:  durchschnittliche Zeit, LLM für Beantwortung einer Frage, getrennt nach korrekt und inkorrekt
Aussagekraft: korrekte Antworten mehr oder weniger Zeit benötigt? Indikator für Schwierigkeiten mit Kontext?

Durchschnittlicher F1 Score (Textvergleich):

Definition: harmonisches Mittel aus Präzision und Recall --> hier verwendet, um Überlappung von Wörtern (Tokens) zwischen der generierten Antwort des LLM und der 'Ground Truth'-Antwort zu messen
Präzision: Wie viele der vom LLM generierten Wörter waren in der 'Ground Truth'?
Recall: Wie viele der Wörter in der 'Ground Truth' wurden vom LLM generiert?
Aussagekraft: Incorrect --> kann ein höherer F1-Score darauf hinweisen, dass die Antwort des LLM inhaltlich dennoch relevante oder ähnliche Informationen enthielt, robuster als EM

EM Score (Exact Match Score):

Definition: Der EM-Score ist in deinem Skript identisch mit der Accuracy, da er misst, ob die LLM-Antwort exakt mit der 'Ground Truth' übereinstimmt, was durch deine binäre 'Correctness'-Spalte repräsentiert wird.
Aussagekraft: 

#-#Erweiterungen, Aussagen und Probleme des Skripts #-#

1. EM + Accuracy aktuell gleiches Maß
2. Fehlerkategorisierung 
3. Performance nach Frage-Typ/Domäne
4. Signifikanztests
5. Accuracy/EM von 0.0000 für QO/RAG
6. Extrem hohe Antwortlänge + Dauer bei Choices (Korrekt)

Idee für die Erweiterung:
Judge LLM für "Fehler" bei Accuracy


"""