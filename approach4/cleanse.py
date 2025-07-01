import csv

INPUT_CSV_FILE = "approach4_post.csv"
OUTPUT_CSV_FILE = "approach4_post_cleansed.csv"
COLUMN_TO_CHECK = "Answer"
VALID_FIRST_CHARS = {"A", "B", "C", "D"}


with open(INPUT_CSV_FILE, mode="r", newline="", encoding="utf-8") as infile, open(
    OUTPUT_CSV_FILE, mode="w", newline="", encoding="utf-8"
) as outfile:

    reader = csv.DictReader(infile)
    writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)

    writer.writeheader()

    processed_count = 0
    skipped_count = 0

    for row in reader:
        answer_value = row.get(COLUMN_TO_CHECK, "").strip()

        if answer_value:
            first_char = answer_value[0]

            if first_char in VALID_FIRST_CHARS:
                row[COLUMN_TO_CHECK] = first_char
                writer.writerow(row)
                processed_count += 1
