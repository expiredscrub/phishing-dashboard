
# Phishing Email Detector with Risk Scoring
# CSIT040 - Project 10
#
# This program checks a pasted email for phishing keywords,
# gives it a risk score, classifies it, and highlights suspicious words.

import re
import csv
import os
from datetime import datetime

KEYWORDS_FILE = "keywords.txt"
RESULTS_FILE = "results.csv"

# ---------------------------------------------------------------
# STEP 1: The list of suspicious keywords and their points.
# More dangerous words get more points.
# ---------------------------------------------------------------
DEFAULT_KEYWORDS = {
    "urgent": 2,
    "verify": 2,
    "password": 3,
    "click here": 2,
    "bank": 1,
    "account suspended": 3,
    "login": 1,
    "winner": 2,
    "free": 1,
    "limited time": 2,
}


# ---------------------------------------------------------------
# STEP 2: Save and load keywords, so new keywords are remembered.
# Each line of keywords.txt looks like:  urgent,2
# ---------------------------------------------------------------
def save_keywords(keywords):
    with open(KEYWORDS_FILE, "w", encoding="utf-8") as f:
        for word, points in keywords.items():
            f.write(f"{word},{points}\n")


def load_keywords():
    if not os.path.exists(KEYWORDS_FILE):
        save_keywords(DEFAULT_KEYWORDS)
        return dict(DEFAULT_KEYWORDS)
    keywords = {}
    with open(KEYWORDS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "," in line:
                word, points = line.rsplit(",", 1)
                keywords[word] = int(points)
    return keywords


# ---------------------------------------------------------------
# STEP 3: Read the pasted email (many lines) until the user types END.
# ---------------------------------------------------------------
def get_email_text():
    print("Paste the email below. Type END on a new line when finished:")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------
# STEP 4: Find the keywords and count how many times each appears.
# \b = whole words only, IGNORECASE = upper/lower case both count.
# ---------------------------------------------------------------
def find_keywords(text, keywords):
    found = {}
    for word in keywords:
        pattern = r"\b" + re.escape(word) + r"\b"
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            found[word] = len(matches)
    return found


# ---------------------------------------------------------------
# STEP 5: Calculate the risk score (points x number of times found).
# ---------------------------------------------------------------
def calculate_score(found, keywords):
    score = 0
    for word, count in found.items():
        score += keywords[word] * count
    return score


# ---------------------------------------------------------------
# STEP 6: Classify the email using the thresholds from the project sheet.
# ---------------------------------------------------------------
def classify(score):
    if score < 3:
        return "Safe"
    elif score <= 5:
        return "Suspicious"
    else:
        return "High Risk"


# ---------------------------------------------------------------
# STEP 7: Highlight suspicious words, e.g. "click here" -> [CLICK HERE]
# ---------------------------------------------------------------
def highlight(text, found):
    for word in found:
        pattern = r"\b(" + re.escape(word) + r")\b"
        text = re.sub(pattern, lambda m: "[" + m.group(1).upper() + "]",
                      text, flags=re.IGNORECASE)
    return text


# ---------------------------------------------------------------
# STEP 8: Let the user add a new keyword.
# ---------------------------------------------------------------
def add_keyword(keywords):
    word = input("New keyword or phrase: ").strip().lower()
    if not word:
        print("Nothing entered.")
        return
    if word in keywords:
        print("That keyword is already in the list.")
        return
    try:
        points = int(input("Points for this keyword (1-3): "))
    except ValueError:
        print("Please enter a number.")
        return
    keywords[word] = points
    save_keywords(keywords)
    print(f"Added '{word}' worth {points} point(s).")


# ---------------------------------------------------------------
# STEP 9 (bonus): Save each result to a CSV file and show statistics.
# ---------------------------------------------------------------
def save_result(text, score, level):
    new_file = not os.path.exists(RESULTS_FILE)
    with open(RESULTS_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["date_time", "preview", "score", "risk_level"])
        preview = text[:50].replace("\n", " ")
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M"),
                         preview, score, level])


def show_stats():
    if not os.path.exists(RESULTS_FILE):
        print("No emails checked yet.")
        return
    with open(RESULTS_FILE, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    counts = {"Safe": 0, "Suspicious": 0, "High Risk": 0}
    for row in rows:
        counts[row["risk_level"]] = counts.get(row["risk_level"], 0) + 1
    print(f"\nTotal emails checked: {len(rows)}")
    for level, n in counts.items():
        print(f"  {level}: {n}")


# ---------------------------------------------------------------
# STEP 10: Check one email from start to finish.
# ---------------------------------------------------------------
def analyze_email(keywords):
    text = get_email_text()
    if not text.strip():
        print("No text entered.")
        return
    found = find_keywords(text, keywords)
    score = calculate_score(found, keywords)
    level = classify(score)

    print("\n========== RESULT ==========")
    print(highlight(text, found))
    print("\nSuspicious keywords found:")
    if found:
        for word, count in found.items():
            print(f"  - {word}: {count} time(s) x {keywords[word]} pts")
    else:
        print("  (none)")
    print(f"\nRisk score: {score}")
    print(f"Risk level: {level}")
    save_result(text, score, level)


# ---------------------------------------------------------------
# STEP 11: The main menu that connects everything.
# ---------------------------------------------------------------
def main():
    keywords = load_keywords()
    while True:
        print("\n=== Phishing Email Detector ===")
        print("1. Check an email")
        print("2. Add a new keyword")
        print("3. View keyword list")
        print("4. View statistics")
        print("5. Exit")
        try:
            choice = input("Choose an option: ").strip()
        except EOFError:
            break
        if choice == "1":
            analyze_email(keywords)
        elif choice == "2":
            add_keyword(keywords)
        elif choice == "3":
            for word, points in keywords.items():
                print(f"  {word} ({points} pts)")
        elif choice == "4":
            show_stats()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice, try again.")


if __name__ == "__main__":
    main()
