# Phishing Email Detector - Streamlit Dashboard
# CSIT040 - Project 10
#
# This file is ONLY the web interface (the "front end").
# All the real logic (finding keywords, scoring, classifying) lives in
# phishing_detector.py, and we just import it here.
#
# Run with:   streamlit run app.py

import os
import re
import pandas as pd
import streamlit as st

from phishing_detector import (
    load_keywords, save_keywords, find_keywords, calculate_score,
    classify, save_result, RESULTS_FILE,
)

# ---------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------
st.set_page_config(page_title="Phishing Email Detector", page_icon="🛡️", layout="wide")
st.title("🛡️ Phishing Email Detector")
st.caption("CSIT040 - Project 10")

keywords = load_keywords()

# Colours for each risk level
LEVEL_COLOURS = {"Safe": "green", "Suspicious": "orange", "High Risk": "red"}


# Same idea as highlight() in the original program, but uses an HTML
# <mark> tag so the word shows up with a yellow background in the browser.
def highlight_html(text, found):
    for word in found:
        pattern = r"\b(" + re.escape(word) + r")\b"
        text = re.sub(pattern, lambda m: "<mark>" + m.group(1).upper() + "</mark>",
                      text, flags=re.IGNORECASE)
    return text.replace("\n", "<br>")


# ---------------------------------------------------------------
# Three tabs = the old menu options, but on a web page
# ---------------------------------------------------------------
tab_check, tab_keywords, tab_stats = st.tabs(["📧 Check Email", "🔑 Keywords", "📊 Statistics"])

# ---------- TAB 1: Check an email ----------
with tab_check:
    email = st.text_area("Paste the email here:", height=250)

    if st.button("Analyze", type="primary"):
        if not email.strip():
            st.warning("No text entered.")
        else:
            found = find_keywords(email, keywords)
            score = calculate_score(found, keywords)
            level = classify(score)
            save_result(email, score, level)

            # Big number cards at the top
            col1, col2, col3 = st.columns(3)
            col1.metric("Risk score", score)
            col2.markdown(f"**Risk level**  \n### :{LEVEL_COLOURS[level]}[{level}]")
            col3.metric("Keywords found", len(found))

            st.subheader("Highlighted email")
            st.markdown(highlight_html(email, found), unsafe_allow_html=True)

            st.subheader("Breakdown")
            if found:
                rows = [{"Keyword": w, "Times found": c, "Points each": keywords[w],
                         "Total": c * keywords[w]} for w, c in found.items()]
                st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
            else:
                st.write("No suspicious keywords found.")

# ---------- TAB 2: View and add keywords ----------
with tab_keywords:
    left, right = st.columns(2)

    with left:
        st.subheader("Current keywords")
        kw_table = pd.DataFrame(list(keywords.items()), columns=["Keyword", "Points"])
        st.dataframe(kw_table, hide_index=True, width="stretch")

    with right:
        st.subheader("Add a new keyword")
        with st.form("add_form", clear_on_submit=True):
            new_word = st.text_input("Keyword or phrase").strip().lower()
            new_points = st.slider("Points", 1, 3, 2)
            if st.form_submit_button("Add"):
                if not new_word:
                    st.error("Nothing entered.")
                elif new_word in keywords:
                    st.error("That keyword is already in the list.")
                else:
                    keywords[new_word] = new_points
                    save_keywords(keywords)
                    st.success(f"Added '{new_word}' worth {new_points} point(s).")
                    st.rerun()

# ---------- TAB 3: Statistics ----------
with tab_stats:
    if not os.path.exists(RESULTS_FILE):
        st.info("No emails checked yet.")
    else:
        df = pd.read_csv(RESULTS_FILE)
        counts = df["risk_level"].value_counts().reindex(
            ["Safe", "Suspicious", "High Risk"], fill_value=0)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total checked", len(df))
        c2.metric("Safe", counts["Safe"])
        c3.metric("Suspicious", counts["Suspicious"])
        c4.metric("High Risk", counts["High Risk"])

        st.subheader("Emails by risk level")
        st.bar_chart(counts)

        st.subheader("History")
        st.dataframe(df.iloc[::-1], hide_index=True, width="stretch")
