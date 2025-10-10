import requests
from bs4 import BeautifulSoup
import csv

def scrape_cvefeed(url):
    resp = requests.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")

    # Données ciblées
    data = {}

    # Type de vulnérabilité (ex: Information Disclosure)
    info_disclosure = soup.find(text="Information Disclosure")
    data["vulnerability_type"] = info_disclosure.strip() if info_disclosure else None

    # Description
    desc_header = soup.find("h6", string="Description")
    desc_content = desc_header.find_next("div") if desc_header else None
    data["description"] = desc_content.get_text(strip=True) if desc_content else None

    # Published Date
    published_label = soup.find(string="Published Date :")
    published = published_label.find_next("h6") if published_label else None
    data["published_date"] = published.get_text(strip=True) if published else None

    # Source
    source_label = soup.find(string="Source :")
    source = source_label.find_next("h6") if source_label else None
    data["source"] = source.get_text(strip=True) if source else None

    # Remotely Exploit
    remote_label = soup.find(string="Remotely Exploit :")
    remote = remote_label.find_next("h6") if remote_label else None
    data["remotely_exploit"] = remote.get_text(strip=True) if remote else None

    # Solution
    solution_header = soup.find("h6", string="Solution")
    solutions = []
    if solution_header:
        ul = solution_header.find_next("ul")
        if ul:
            solutions = [li.get_text(strip=True) for li in ul.find_all("li")]
        else:
            # parfois sous forme de texte simple :
            sol = solution_header.find_next("div")
            if sol:
                solutions = [sol.get_text(strip=True)]
    data["solution"] = "; ".join(solutions)

    # CVSS Scores (table)
    cvss_table = soup.find("table")
    if cvss_table:
        rows = cvss_table.find_all("tr")
        cols = [c.get_text(strip=True) for c in rows[1].find_all("td")] if len(rows) > 1 else []
        if cols and len(cols) >= 7:
            data["score"] = cols[0]
            data["version"] = cols[1]
            data["severity"] = cols[2]
            data["vector"] = cols[3]
            data["exploitability_score"] = cols[4]
            data["impact_score"] = cols[5]
            data["score_source"] = cols[6]
        else:
            # champs vides si absent
            for field in ["score","version","severity","vector","exploitability_score","impact_score","score_source"]:
                data[field] = None

    # Vulnerability Scoring Details 
    # Attack vector, complexity, privileges, user interaction, scope, confidentiality, integrity, availability (via radio aria-labels)
    def get_radio_value(label):
        input_tag = soup.find("input", attrs={"aria-label": label, "checked": True})
        return input_tag["aria-label"] if input_tag else None

    data["attack_vector"] = get_radio_value("Network") or get_radio_value("Adjacent") or get_radio_value("Local") or get_radio_value("Physical")
    data["attack_complexity"] = get_radio_value("Low") or get_radio_value("High")
    data["privileges_required"] = get_radio_value("Low") or get_radio_value("High") or get_radio_value("None")
    data["user_interaction"] = get_radio_value("None") or get_radio_value("Required")
    data["scope"] = get_radio_value("Changed") or get_radio_value("Unchanged")
    data["confidentiality_impact"] = get_radio_value("High") or get_radio_value("Low") or get_radio_value("None")
    data["integrity_impact"] = get_radio_value("High") or get_radio_value("Low") or get_radio_value("None")
    data["availability_impact"] = get_radio_value("High") or get_radio_value("Low") or get_radio_value("None")

    # Affected product
    affected_section = soup.find("h6", string="Affected Products")
    data["affected_product"] = "None" if affected_section and "No affected product" in affected_section.find_next("div").text else None

    # Création CSV (appends, header si nouveau)
    csv_file = "cvefeed_scraped.csv"
    fields = [
        "vulnerability_type",
        "description",
        "published_date",
        "source",
        "remotely_exploit",
        "affected_product",
        "solution",
        "score","version","severity","vector","exploitability_score","impact_score","score_source",
        "attack_vector","attack_complexity","privileges_required","user_interaction","scope",
        "confidentiality_impact","integrity_impact","availability_impact"
    ]
    write_header = False
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            pass
    except FileNotFoundError:
        write_header = True

    with open(csv_file, "a", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if write_header:
            writer.writeheader()
        writer.writerow(data)
    print("Infos sauvegardées dans", csv_file)

# Exemple d'utilisation
scrape_cvefeed("https://cvefeed.io/vuln/detail/CVE-2025-0001")
