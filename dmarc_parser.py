#!/usr/bin/env python3
import argparse
import sys
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
import mysql.connector

def parse_dmarc_report(file_path):
    """
    Versucht, die XML-Datei zu parsen. Bei Fehlern wird eine aussagekräftige
    Fehlermeldung ausgegeben und das Programm beendet.
    """
    try:
        tree = ET.parse(file_path)
        return tree.getroot()
    except FileNotFoundError:
        print(f"Fehler: Die Datei '{file_path}' wurde nicht gefunden.")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"Fehler beim Parsen der XML-Datei: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")
        sys.exit(1)

def extract_report_metadata(root):
    """
    Extrahiert die Metadaten aus dem <report_metadata>-Element.
    Erwartete Elemente: org_name, email, report_id, date_range (begin und end)
    """
    report_metadata = root.find("report_metadata")
    if report_metadata is None:
        print("Fehler: Kein <report_metadata>-Element im XML gefunden.")
        sys.exit(1)

    org_name = report_metadata.find("org_name").text if report_metadata.find("org_name") is not None else ""
    email = report_metadata.find("email").text if report_metadata.find("email") is not None else ""
    report_id = report_metadata.find("report_id").text if report_metadata.find("report_id") is not None else ""

    date_range_elem = report_metadata.find("date_range")
    if date_range_elem is not None:
        begin_text = date_range_elem.find("begin").text if date_range_elem.find("begin") is not None else ""
        end_text = date_range_elem.find("end").text if date_range_elem.find("end") is not None else ""

        try:
            timestamp_begin = int(begin_text)
            date_range_begin = datetime.fromtimestamp(timestamp_begin, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            date_range_begin = begin_text

        try:
            timestamp_end = int(end_text)
            date_range_end = datetime.fromtimestamp(timestamp_end, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            date_range_end = end_text

    else:
        date_range_begin, date_range_end = "", ""

    return org_name, email, report_id, date_range_begin, date_range_end

def parse_records(root):
    """
    Durchläuft alle <record>-Elemente im XML und speichert diese als Dictionary in einer Liste.
    """
    records = []
    for record in root.findall("record"):
        # Parsing des <row>-Elements
        row_elem = record.find("row")
        if row_elem is not None:
            source_ip = row_elem.find("source_ip").text if row_elem.find("source_ip") is not None else ""
            count = row_elem.find("count").text if row_elem.find("count") is not None else ""
            policy_evaluated_elem = row_elem.find("policy_evaluated")
            if policy_evaluated_elem is not None:
                disposition = policy_evaluated_elem.find("disposition").text if policy_evaluated_elem.find("disposition") is not None else ""
                dkim_policy = policy_evaluated_elem.find("dkim").text if policy_evaluated_elem.find("dkim") is not None else ""
                spf_policy = policy_evaluated_elem.find("spf").text if policy_evaluated_elem.find("spf") is not None else ""
            else:
                disposition, dkim_policy, spf_policy = "", "", ""
        else:
            source_ip, count, disposition, dkim_policy, spf_policy = "", "", "", "", ""

        # Parsing des <identifiers>-Elements
        identifiers_elem = record.find("identifiers")
        if identifiers_elem is not None:
            envelope_to = identifiers_elem.find("envelope_to").text if identifiers_elem.find("envelope_to") is not None else ""
            envelope_from = identifiers_elem.find("envelope_from").text if identifiers_elem.find("envelope_from") is not None else ""
            header_from = identifiers_elem.find("header_from").text if identifiers_elem.find("header_from") is not None else ""
        else:
            envelope_to, envelope_from, header_from = "", "", ""

        # Parsing des optionalen <auth_results>-Elements
        auth_results_elem = record.find("auth_results")
        dkim_auth = {}
        spf_auth = {}
        if auth_results_elem is not None:
            dkim_elem = auth_results_elem.find("dkim")
            if dkim_elem is not None:
                dkim_auth = {
                    "domain": dkim_elem.find("domain").text if dkim_elem.find("domain") is not None else "",
                    "selector": dkim_elem.find("selector").text if dkim_elem.find("selector") is not None else "",
                    "result": dkim_elem.find("result").text if dkim_elem.find("result") is not None else ""
                }
            spf_elem = auth_results_elem.find("spf")
            if spf_elem is not None:
                spf_auth = {
                    "domain": spf_elem.find("domain").text if spf_elem.find("domain") is not None else "",
                    "scope": spf_elem.find("scope").text if spf_elem.find("scope") is not None else "",
                    "result": spf_elem.find("result").text if spf_elem.find("result") is not None else ""
                }

        record_dict = {
            "row": {
                "source_ip": source_ip,
                "count": count,
                "policy_evaluated": {
                    "disposition": disposition,
                    "dkim": dkim_policy,
                    "spf": spf_policy
                }
            },
            "identifiers": {
                "envelope_to": envelope_to,
                "envelope_from": envelope_from,
                "header_from": header_from
            },
            "auth_results": {
                "dkim": dkim_auth,
                "spf": spf_auth
            }
        }
        records.append(record_dict)
    return records

def write_to_database(report_metadata, records, db_config):
    """
    Schreibt die Report-Metadaten und alle Record-Datensätze in die MySQL-Datenbank.

    :param report_metadata: Tuple (org_name, email, report_id, date_range_begin, date_range_end)
    :param records: Liste von Dictionaries, die einzelne Record-Datensätze repräsentieren
    :param db_config: Dictionary mit Datenbank-Konfigurationsparametern, z. B.
                      {
                          "host": "localhost",
                          "user": "dein_benutzer",
                          "password": "dein_passwort",
                          "database": "dmarc_db"
                      }
    """
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # 1. Insert Report-Metadaten in dmarc_reports
        insert_report_query = """
            INSERT INTO reports (report_id, org_name, email, date_range_begin, date_range_end)
            VALUES (%s, %s, %s, %s, %s)
        """
        org_name, email, report_id, date_range_begin, date_range_end = report_metadata
        cursor.execute(insert_report_query, (report_id, org_name, email, date_range_begin, date_range_end))
        conn.commit()
        report_db_id = cursor.lastrowid
        print(f"Inserted report with id {report_db_id}")

        # 2. Prepare Queries für Record-Datensätze und Authentifizierungsergebnisse
        insert_record_query = """
            INSERT INTO records
                (report_id, source_ip, count, disposition, dkim_policy, spf_policy,
                 envelope_to, envelope_from, header_from)
            VALUES (%s, INET6_ATON(%s), %s, %s, %s, %s, %s, %s, %s)
        """
        insert_dkim_query = """
            INSERT INTO auth_dkim (record_id, domain, selector, result)
            VALUES (%s, %s, %s, %s)
        """
        insert_spf_query = """
            INSERT INTO auth_spf (record_id, domain, scope, result)
            VALUES (%s, %s, %s, %s)
        """

        # 3. Gehe alle Records durch und schreibe sie in die DB
        for record in records:
            row = record.get("row", {})
            identifiers = record.get("identifiers", {})

            try:
                count_val = int(row.get("count", ""))
            except (ValueError, TypeError):
                count_val = None

            policy_evaluated = row.get("policy_evaluated", {})
            disposition = policy_evaluated.get("disposition")
            dkim_policy = policy_evaluated.get("dkim")
            spf_policy = policy_evaluated.get("spf")

            cursor.execute(insert_record_query, (
                report_db_id,
                row.get("source_ip"),
                count_val,
                disposition,
                dkim_policy,
                spf_policy,
                identifiers.get("envelope_to"),
                identifiers.get("envelope_from"),
                identifiers.get("header_from")
            ))
            conn.commit()
            record_db_id = cursor.lastrowid

            # Insert DKIM auth results, falls vorhanden
            dkim_auth = record.get("auth_results", {}).get("dkim", {})
            if dkim_auth and dkim_auth.get("result"):
                cursor.execute(insert_dkim_query, (
                    record_db_id,
                    dkim_auth.get("domain"),
                    dkim_auth.get("selector"),
                    dkim_auth.get("result")
                ))
                conn.commit()

            # Insert SPF auth results, falls vorhanden
            spf_auth = record.get("auth_results", {}).get("spf", {})
            if spf_auth and spf_auth.get("result"):
                cursor.execute(insert_spf_query, (
                    record_db_id,
                    spf_auth.get("domain"),
                    spf_auth.get("scope"),
                    spf_auth.get("result")
                ))
                conn.commit()

        cursor.close()
        conn.close()
        print("Daten erfolgreich in die Datenbank geschrieben.")
    except mysql.connector.Error as err:
        print("MySQL Fehler:", err)

def main():
    parser = argparse.ArgumentParser(
        description="Liest einen DMARC XML Report ein, extrahiert die Report-Metadaten, parst alle Record-Datensätze in ein Array und schreibt die Daten in eine MySQL-Datenbank."
    )
    parser.add_argument("xmlfile", help="Pfad zur DMARC XML-Datei")
    args = parser.parse_args()

    root = parse_dmarc_report(args.xmlfile)

    # Report-Metadaten extrahieren
    org_name, email, report_id, date_range_begin, date_range_end = extract_report_metadata(root)

    # Überprüfen, ob wichtige Metadaten vorhanden sind
    if not org_name or not report_id or not date_range_begin or not date_range_end:
        print("Fehler: org_name, report_id, date_range_begin oder date_range_end sind leer. Das Skript wird beendet.")
        sys.exit(1)

    print("Report Metadata:")
    print(f"  Org Name: {org_name}")
    print(f"  Email: {email}")
    print(f"  Report ID: {report_id}")
    print(f"  Date Range Begin: {date_range_begin}")
    print(f"  Date Range End: {date_range_end}\n")

    # Alle Record-Datensätze parsen
    records = parse_records(root)

    # Datenbank-Konfiguration (bitte anpassen)
    db_config = {
        "host": "localhost",
        "user": "root",
        "password": "",
        "database": "dmarc_report"
    }

    # Daten in die Datenbank schreiben
    write_to_database((org_name, email, report_id, date_range_begin, date_range_end), records, db_config)

if __name__ == "__main__":
    main()
