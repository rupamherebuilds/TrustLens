import json
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

# Get the directory where this db.py file is located.
# This directory will be used for storing the default database.
BASE_DIR = Path(__file__).resolve().parent


def get_db_path():
    """
    Return the database file path.

    If DB_PATH environment variable is available, use that path.
    Otherwise, use backend/trustlens.db as the default database.
    """

    return os.getenv(
        "DB_PATH",
        str(BASE_DIR / "trustlens.db")
    )


@contextmanager
def get_connection():
    """
    Create and manage a SQLite database connection.

    Steps:
    1. Open a connection to the database.
    2. Enable dictionary-like access to database rows.
    3. Provide the connection to the calling function.
    4. Automatically close the connection after use.

    This prevents database connections from remaining open.
    """

    # Connect to the configured SQLite database.
    connection = sqlite3.connect(get_db_path())

    # Allow accessing database columns using their names.
    # Example: row["scan_id"] instead of row[0].
    connection.row_factory = sqlite3.Row

    try:
        # Provide the connection to the calling function.
        yield connection

    finally:
        # Always close the connection after the operation.
        connection.close()


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():
    """
    Initialize the TrustLens database.

    Creates two tables if they do not already exist:
    1. scans   -> Stores URL scan results.
    2. reports -> Stores generated verification reports.
    """

    # Open a database connection.
    with get_connection() as connection:

        # ----------------------------------------------------
        # SCANS TABLE
        # ----------------------------------------------------
        # Stores information about completed URL scans.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                label TEXT NOT NULL,
                score INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)

        # ----------------------------------------------------
        # REPORTS TABLE
        # ----------------------------------------------------
        # Stores reports generated from completed scans.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                chain_report_id TEXT,
                report_hash TEXT NOT NULL,
                tx_hash TEXT,
                report_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # Save the table creation changes.
        connection.commit()


# ============================================================
# SCAN MANAGEMENT FUNCTIONS
# ============================================================

def save_scan(result):
    """
    Save a completed URL scan result into the database.

    Parameters:
        result -> Dictionary containing the scan result.

    Returns:
        scan_id -> ID of the saved scan.
    """

    # Convert the complete scan dictionary into JSON.
    # default=str allows serialization of unsupported objects.
    result_json = json.dumps(result, default=str)

    # Extract important scan information for database columns.
    scan_id = result.get("scan_id")
    url = result.get("url")
    host = result.get("host")
    label = result.get("label")
    score = result.get("score")

    # Use the scan timestamp if available.
    # Otherwise, generate the current UTC timestamp.
    checked_at = result.get(
        "checked_at",
        datetime.now(timezone.utc).isoformat()
    )

    # Open a database connection.
    with get_connection() as connection:

        # Insert the scan into the scans table.
        # If the same scan_id already exists, replace its record.
        connection.execute("""
            INSERT OR REPLACE INTO scans
            (scan_id, url, host, label, score, checked_at, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            url,
            host,
            label,
            score,
            checked_at,
            result_json
        ))

        # Commit the scan data to the database.
        connection.commit()

    # Return the ID of the saved scan.
    return scan_id


def get_scan(scan_id):
    """
    Retrieve a previously saved scan using its scan ID.

    Parameters:
        scan_id -> Unique identifier of the scan.

    Returns:
        Dictionary containing the scan result.
        None if the scan does not exist.
    """

    # Open a database connection.
    with get_connection() as connection:

        # Search for the scan using its unique ID.
        row = connection.execute("""
            SELECT result_json
            FROM scans
            WHERE scan_id = ?
        """, (scan_id,)).fetchone()

    # If no matching scan exists, return None.
    if row is None:
        return None

    # Convert the stored JSON back into a Python dictionary.
    return json.loads(row["result_json"])


def list_scans(limit=200):
    """
    Retrieve the most recent saved URL scans.

    Parameters:
        limit -> Maximum number of scans to retrieve.
                Default value is 200.

    Returns:
        List of scan result dictionaries.
    """

    # Open a database connection.
    with get_connection() as connection:

        # Retrieve scans ordered by their timestamp.
        # Newest scans appear first.
        rows = connection.execute("""
            SELECT result_json
            FROM scans
            ORDER BY checked_at DESC
            LIMIT ?
        """, (limit,)).fetchall()

    # Convert every stored JSON result into a Python dictionary.
    return [
        json.loads(row["result_json"])
        for row in rows
    ]


# ============================================================
# REPORT MANAGEMENT FUNCTIONS
# ============================================================

def save_report(
    scan_id,
    report_json,
    report_hash,
    chain_report_id,
    tx_hash
):
    """
    Save a verification report associated with a URL scan.

    Parameters:
        scan_id         -> ID of the original scan.
        report_json     -> Report data in dictionary format.
        report_hash     -> Hash generated for report verification.
        chain_report_id -> Identifier of the blockchain report.
        tx_hash         -> Blockchain transaction hash.

    Returns:
        ID of the newly inserted report record.
    """

    # Generate the current UTC timestamp for the report.
    created_at = datetime.now(timezone.utc).isoformat()

    # Open a database connection.
    with get_connection() as connection:

        # Insert the report into the reports table.
        cursor = connection.execute("""
            INSERT INTO reports
            (scan_id, chain_report_id, report_hash, tx_hash,
             report_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            chain_report_id,
            report_hash,
            tx_hash,
            json.dumps(report_json, default=str),
            created_at
        ))

        # Commit the report data.
        connection.commit()

        # Return the automatically generated database record ID.
        return cursor.lastrowid


def get_report(chain_report_id):
    """
    Retrieve a saved report using its blockchain report ID.

    Parameters:
        chain_report_id -> Identifier of the blockchain report.

    Returns:
        Dictionary containing report information.
        None if the report does not exist.
    """

    # Open a database connection.
    with get_connection() as connection:

        # Search for the report using its blockchain report ID.
        row = connection.execute("""
            SELECT *
            FROM reports
            WHERE chain_report_id = ?
        """, (chain_report_id,)).fetchone()

    # Return None if no matching report exists.
    if row is None:
        return None

    # Convert the SQLite row into a normal Python dictionary.
    report = dict(row)

    # Convert the stored report JSON into a Python dictionary.
    report["report_json"] = json.loads(report["report_json"])

    # Return the complete report information.
    return report


def list_reports():
    """
    Retrieve all saved verification reports.

    Returns:
        List of report dictionaries ordered by creation time.
        Newest reports appear first.
    """

    # Open a database connection.
    with get_connection() as connection:

        # Retrieve all reports from the database.
        rows = connection.execute("""
            SELECT *
            FROM reports
            ORDER BY created_at DESC
        """).fetchall()

    # Prepare a list to store converted report dictionaries.
    reports = []

    # Convert every SQLite row into a Python dictionary.
    for row in rows:

        report = dict(row)

        # Convert the stored report JSON into a Python dictionary.
        report["report_json"] = json.loads(report["report_json"])

        # Add the converted report to the list.
        reports.append(report)

    # Return all retrieved reports.
    return reports


# ============================================================
# DATABASE SELF-CHECK
# ============================================================
# This section runs only when db.py is executed directly.
#
# Example:
#     python db.py
#
# It uses a temporary database to test the database functions.
# The actual TrustLens database remains untouched.
# ============================================================

if __name__ == "__main__":

    # Import tempfile for creating a temporary testing directory.
    import tempfile

    print("\n========== TrustLens DB Self-Check ==========\n")

    # Store the original database configuration.
    original_db_path = os.environ.get("DB_PATH")

    try:

        # Create a temporary directory for testing.
        with tempfile.TemporaryDirectory() as temp_dir:

            # Configure the self-check to use a temporary database.
            os.environ["DB_PATH"] = str(
                Path(temp_dir) / "test_trustlens.db"
            )

            # ------------------------------------------------
            # TEST 1: DATABASE INITIALIZATION
            # ------------------------------------------------

            # Create the scans and reports tables.
            init_db()

            print("[PASS] Database initialization")

            # ------------------------------------------------
            # TEST 2: SAVE SCAN
            # ------------------------------------------------

            # Create a sample scan result.
            test_scan = {
                "scan_id": "test_scan_001",
                "url": "https://example.com",
                "host": "example.com",
                "label": "Low Risk",
                "score": 10,
                "checked_at": datetime.now(timezone.utc).isoformat()
            }

            # Save the sample scan.
            save_scan(test_scan)

            print("[PASS] Save scan")

            # ------------------------------------------------
            # TEST 3: GET SCAN
            # ------------------------------------------------

            # Retrieve the saved scan using its ID.
            retrieved_scan = get_scan("test_scan_001")

            # Verify that the retrieved scan matches the original.
            assert retrieved_scan == test_scan

            print("[PASS] Get scan")

            # ------------------------------------------------
            # TEST 4: LIST SCANS
            # ------------------------------------------------

            # Retrieve all saved scans.
            scans = list_scans()

            # Verify that exactly one scan exists.
            assert len(scans) == 1

            # Verify the scan ID.
            assert scans[0]["scan_id"] == "test_scan_001"

            print("[PASS] List scans")

            # ------------------------------------------------
            # TEST 5: SAVE REPORT
            # ------------------------------------------------

            # Create a sample verification report.
            test_report = {
                "title": "TrustLens Test Report",
                "status": "verified"
            }

            # Save the sample report.
            save_report(
                scan_id="test_scan_001",
                report_json=test_report,
                report_hash="test_hash_123",
                chain_report_id="test_chain_001",
                tx_hash="test_tx_001"
            )

            print("[PASS] Save report")

            # ------------------------------------------------
            # TEST 6: GET REPORT
            # ------------------------------------------------

            # Retrieve the saved report.
            retrieved_report = get_report("test_chain_001")

            # Verify the report content.
            assert retrieved_report["report_json"] == test_report

            # Verify the associated scan ID.
            assert retrieved_report["scan_id"] == "test_scan_001"

            print("[PASS] Get report")

            # ------------------------------------------------
            # TEST 7: LIST REPORTS
            # ------------------------------------------------

            # Retrieve all saved reports.
            reports = list_reports()

            # Verify that exactly one report exists.
            assert len(reports) == 1

            # Verify the blockchain report ID.
            assert reports[0]["chain_report_id"] == "test_chain_001"

            print("[PASS] List reports")

            # ------------------------------------------------
            # TEST 8: MISSING RECORD HANDLING
            # ------------------------------------------------

            # Verify that a missing scan returns None.
            assert get_scan("missing_scan") is None

            # Verify that a missing report returns None.
            assert get_report("missing_report") is None

            print("[PASS] Missing record handling")

        # Display the final success message.
        print("\n========== ALL DATABASE TESTS PASSED ==========\n")

    except Exception as error:

        # Display the failure message if any test fails.
        print(f"\n[FAIL] Database self-check: {error}")

        # Re-raise the error so Python displays the traceback.
        raise

    finally:

        # Restore the original database configuration.
        # This prevents the temporary DB path from affecting
        # normal TrustLens database operations.
        if original_db_path is None:

            # Remove DB_PATH if it was originally absent.
            os.environ.pop("DB_PATH", None)

        else:

            # Restore the previously configured DB_PATH.
            os.environ["DB_PATH"] = original_db_path