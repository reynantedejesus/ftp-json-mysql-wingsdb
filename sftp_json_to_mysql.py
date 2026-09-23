#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sftp_json_to_mysql.py
=====================

Downloads all ``*.json`` files from an SFTP directory, combines their parsed
contents into one JSON array, stores that array as a single row in the MySQL
table ``ext_externalApplicationInbox`` and finally moves the processed files
into a "processed" sub-folder on the SFTP server.

Designed to run unattended (e.g. from cron) on Rocky Linux 9 with Python 3.9+.

-------------------------------------------------------------------------------
requirements.txt
-------------------------------------------------------------------------------
    paramiko>=3.4,<4
    mysql-connector-python>=8.0.33

-------------------------------------------------------------------------------
Usage (Rocky Linux 9)
-------------------------------------------------------------------------------
    # 1. System packages (once)
    sudo dnf install -y python3 python3-pip

    # 2. Create and activate a virtual environment
    python3 -m venv /opt/wings-sftp-import/venv
    source /opt/wings-sftp-import/venv/bin/activate

    # 3. Install dependencies
    pip install --upgrade pip
    pip install -r requirements.txt

    # 4. Provide credentials (see "Security notes" below) and run
    python sftp_json_to_mysql.py

    # Only test the SFTP login and list the files (no MySQL, nothing moved)
    python sftp_json_to_mysql.py --test-connection

    # Optional: verbose logging
    LOG_LEVEL=DEBUG python sftp_json_to_mysql.py

    # Example cron entry (every 15 minutes), credentials in an env file
    # that is only readable by the service user (chmod 600):
    # */15 * * * * set -a; . /etc/wings-sftp-import.env; set +a; \
    #   /opt/wings-sftp-import/venv/bin/python \
    #   /opt/wings-sftp-import/sftp_json_to_mysql.py >> /var/log/wings-sftp-import.log 2>&1

-------------------------------------------------------------------------------
Security notes
-------------------------------------------------------------------------------
    * NEVER commit real passwords to version control. The defaults below are
      placeholders only.
    * Prefer environment variables or a secrets manager (HashiCorp Vault,
      AWS Secrets Manager, systemd credentials, ...) over hard-coded values.
    * Every setting below can be overridden by an environment variable:

        export SFTP_HOST="sftp-dev-edi.infinite.pl"
        export SFTP_PORT="10032"
        export SFTP_USER="wings_travel"
        export SFTP_PASSWORD='********'   # single quotes if it contains $ ! or `
        export SFTP_EXTRA_HOST_KEY_ALGORITHMS="ssh-rsa"  # = -o HostKeyAlgorithms=+ssh-rsa
        export SFTP_REMOTE_DIR="/response"
        export SFTP_PROCESSED_DIR="/response/processed"

        export MYSQL_HOST="127.0.0.1"
        export MYSQL_PORT="3306"
        export MYSQL_USER="wings_import"
        export MYSQL_PASSWORD="********"
        export MYSQL_DATABASE="wings"

    * An env file used by cron/systemd should be ``chmod 600`` and owned by
      the account that runs the job.
    * SFTP host keys are verified against ``SFTP_KNOWN_HOSTS``. With the
      default policy "autoadd" the key is trusted on first use and saved;
      afterwards a changed key aborts the run. Use "reject" in production once
      the key has been recorded (or pre-populate the file with ssh-keyscan).

-------------------------------------------------------------------------------
Exit codes
-------------------------------------------------------------------------------
    0  success (also when there were no JSON files to process)
    1  configuration / unexpected error
    2  SFTP connection or download error
    3  JSON parsing error
    4  MySQL error (files are NOT moved)
    5  data stored in MySQL, but moving one or more files failed
    6  another instance is already running (lock held)
"""

import argparse
import fcntl
import json
import logging
import os
import posixpath
import socket
import stat
import sys
import uuid
from datetime import date, datetime
from typing import Any, List, Optional, Tuple

import mysql.connector
import paramiko
from mysql.connector import Error as MySQLError

# =============================================================================
# CONFIGURATION  --  edit here or (preferably) override via environment vars
# =============================================================================

# --- SFTP --------------------------------------------------------------------
SFTP_HOST = os.environ.get("SFTP_HOST", "sftp-dev-edi.infinite.pl")
SFTP_PORT = int(os.environ.get("SFTP_PORT", "10032"))
SFTP_USER = os.environ.get("SFTP_USER", "wings_travel")
# WARNING: placeholder only - set SFTP_PASSWORD in the environment instead.
# The script refuses to run while the password is still this placeholder.
PLACEHOLDER_SFTP_PASSWORD = "xxxxxxx"
SFTP_PASSWORD = os.environ.get("SFTP_PASSWORD", PLACEHOLDER_SFTP_PASSWORD)
SFTP_REMOTE_DIR = os.environ.get("SFTP_REMOTE_DIR", "/response")
SFTP_PROCESSED_DIR = os.environ.get("SFTP_PROCESSED_DIR", "/response/processed")
SFTP_TIMEOUT_SECONDS = float(os.environ.get("SFTP_TIMEOUT_SECONDS", "30"))
# Host key handling: "autoadd" (trust on first use, then verify),
# "reject" (key must already be in known_hosts), "warn" (accept anything - NOT
# recommended, vulnerable to man-in-the-middle attacks).
SFTP_HOST_KEY_POLICY = os.environ.get("SFTP_HOST_KEY_POLICY", "autoadd").lower()
SFTP_KNOWN_HOSTS = os.environ.get(
    "SFTP_KNOWN_HOSTS", os.path.expanduser("~/.ssh/known_hosts_wings_sftp")
)
# Extra host key algorithms to accept, like "sftp -o HostKeyAlgorithms=+ssh-rsa".
# Comma separated; they are ADDED to paramiko's defaults, nothing is removed.
SFTP_EXTRA_HOST_KEY_ALGORITHMS = [
    a.strip()
    for a in os.environ.get("SFTP_EXTRA_HOST_KEY_ALGORITHMS", "ssh-rsa").split(",")
    if a.strip()
]
JSON_EXTENSION = ".json"
JSON_FILE_ENCODING = "utf-8-sig"  # tolerates an optional UTF-8 BOM

# --- MySQL -------------------------------------------------------------------
MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER = os.environ.get("MYSQL_USER", "wings_import")
# WARNING: placeholder only - set MYSQL_PASSWORD in the environment instead.
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "change_me")
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "wings")
MYSQL_CONNECT_TIMEOUT_SECONDS = int(os.environ.get("MYSQL_CONNECT_TIMEOUT_SECONDS", "15"))

# --- Values written to ext_externalApplicationInbox --------------------------
INBOX_STATUS_NEW = 0                # status: 0 = new / not yet processed by the application
IMPORT_SOURCE = 1                   # importSource: 1 = this SFTP JSON import job
SYSTEM_VERSION_NUMBER = "1.0.0"     # systemVersionNumber: version of this importer
FILE_ID = 0                         # file: 0 (schema default, no linked file record)
EXTERNAL_APPLICATION_INSTANCE = 0   # externalApplicationInstance
EXTERNAL_APP_INSTANCES_TO_LINK_TYPE = 0  # externalApplicationInstancesToLinkType
# creationDateInExternalSystem: "null" -> store NULL, "today" -> store today's date
CREATION_DATE_IN_EXTERNAL_SYSTEM_MODE = os.environ.get(
    "CREATION_DATE_IN_EXTERNAL_SYSTEM_MODE", "null"
).lower()
# externalKey: "<prefix>-<YYYYmmddHHMMSS>-<uuid4 hex>", e.g.
# "SFTPJSON-20260923101500-3f2c9a...". Unique per run and sortable by time.
EXTERNAL_KEY_PREFIX = "SFTPJSON"

# --- Behaviour flags ---------------------------------------------------------
# Sort file names alphabetically so the resulting array order is deterministic
# (raw SFTP directory listings have no guaranteed order).
SORT_FILES_BY_NAME = True
# False: any invalid JSON file aborts the run (nothing is inserted or moved).
# True : invalid files are logged, skipped and left in the remote directory.
SKIP_INVALID_JSON_FILES = os.environ.get("SKIP_INVALID_JSON_FILES", "false").lower() in (
    "1", "true", "yes",
)
# Prevents overlapping runs when started from cron.
LOCK_FILE = os.environ.get("LOCK_FILE", "/tmp/sftp_json_to_mysql.lock")

# --- Logging -----------------------------------------------------------------
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.environ.get("LOG_FILE", "")  # empty = log to stderr only

# =============================================================================
# Exit codes
# =============================================================================
EXIT_OK = 0
EXIT_GENERAL_ERROR = 1
EXIT_SFTP_ERROR = 2
EXIT_JSON_ERROR = 3
EXIT_MYSQL_ERROR = 4
EXIT_MOVE_ERROR = 5
EXIT_ALREADY_RUNNING = 6

INSERT_SQL = """
    INSERT INTO ext_externalApplicationInbox (
      fileContent,
      status,
      inboxCreationDateTime,
      importSource,
      externalKey,
      systemVersionNumber,
      lastImportDateTime,
      file,
      externalApplicationInstance,
      externalApplicationInstancesToLinkType,
      creationDateInExternalSystem
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

log = logging.getLogger("sftp_json_to_mysql")


class JobError(Exception):
    """Error carrying the process exit code to use."""

    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# =============================================================================
# Helpers
# =============================================================================
def setup_logging() -> None:
    handlers: List[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if LOG_FILE:
        handlers.append(logging.FileHandler(LOG_FILE, encoding="utf-8"))
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)-8s [%(process)d] %(message)s",
        handlers=handlers,
    )
    # paramiko is very chatty at INFO level
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def acquire_lock(path: str):
    """Take an exclusive, non-blocking lock so cron runs never overlap."""
    handle = open(path, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise JobError(
            "Another instance is already running (lock file %s)" % path,
            EXIT_ALREADY_RUNNING,
        )
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def generate_external_key(now: datetime) -> str:
    return "%s-%s-%s" % (EXTERNAL_KEY_PREFIX, now.strftime("%Y%m%d%H%M%S"), uuid.uuid4().hex)


def creation_date_in_external_system() -> Optional[date]:
    if CREATION_DATE_IN_EXTERNAL_SYSTEM_MODE == "today":
        return date.today()
    return None


def remote_exists(sftp: paramiko.SFTPClient, path: str) -> bool:
    try:
        sftp.stat(path)
        return True
    except FileNotFoundError:
        return False


def ensure_remote_dir(sftp: paramiko.SFTPClient, path: str) -> None:
    """Create ``path`` (and missing parents) on the SFTP server."""
    parts = [p for p in path.split("/") if p]
    current = "/" if path.startswith("/") else ""
    for part in parts:
        current = posixpath.join(current, part) if current else part
        try:
            attrs = sftp.stat(current)
            if not stat.S_ISDIR(attrs.st_mode or 0):
                raise JobError(
                    "Remote path %s exists but is not a directory" % current, EXIT_MOVE_ERROR
                )
        except FileNotFoundError:
            log.info("Creating remote directory %s", current)
            sftp.mkdir(current)


# =============================================================================
# SFTP
# =============================================================================
def _known_hosts_name() -> str:
    # Same format OpenSSH uses in known_hosts for non-standard ports.
    return SFTP_HOST if SFTP_PORT == 22 else "[%s]:%d" % (SFTP_HOST, SFTP_PORT)


def _verify_host_key(server_key: paramiko.PKey) -> None:
    """Check the server's host key against known_hosts (like OpenSSH does)."""
    host_keys = paramiko.HostKeys()
    for path in (os.path.expanduser("~/.ssh/known_hosts"), SFTP_KNOWN_HOSTS):
        if os.path.exists(path):
            try:
                host_keys.load(path)
            except (IOError, paramiko.SSHException) as exc:
                log.warning("Could not read known_hosts file %s: %s", path, exc)

    name = _known_hosts_name()
    key_type = server_key.get_name()
    fingerprint = server_key.fingerprint
    known = host_keys.lookup(name) or {}

    if key_type in known:
        if known[key_type] != server_key:
            raise paramiko.BadHostKeyException(name, server_key, known[key_type])
        log.debug("Host key for %s verified (%s %s)", name, key_type, fingerprint)
        return

    if SFTP_HOST_KEY_POLICY == "reject":
        raise paramiko.SSHException(
            "Host key for %s (%s %s) is not in %s and SFTP_HOST_KEY_POLICY=reject"
            % (name, key_type, fingerprint, SFTP_KNOWN_HOSTS)
        )
    if SFTP_HOST_KEY_POLICY == "warn":
        log.warning("Unknown host key for %s accepted without saving (%s %s)", name, key_type, fingerprint)
        return

    # "autoadd": trust on first use and remember the key.
    log.warning("Adding new host key for %s to %s (%s %s)", name, SFTP_KNOWN_HOSTS, key_type, fingerprint)
    known_hosts_dir = os.path.dirname(SFTP_KNOWN_HOSTS)
    if known_hosts_dir:
        os.makedirs(known_hosts_dir, mode=0o700, exist_ok=True)
    own_keys = paramiko.HostKeys()
    if os.path.exists(SFTP_KNOWN_HOSTS):
        own_keys.load(SFTP_KNOWN_HOSTS)
    own_keys.add(name, key_type, server_key)
    own_keys.save(SFTP_KNOWN_HOSTS)


def _authenticate(transport: paramiko.Transport) -> None:
    """
    Log in with the password, the way the OpenSSH ``sftp`` client does:
    try "password" authentication and fall back to "keyboard-interactive"
    (many SFTP servers only accept the password through the latter).
    """
    # Ask the server which methods it offers - very useful when debugging.
    try:
        transport.auth_none(SFTP_USER)
        log.info("SFTP server accepted user %s without a password", SFTP_USER)
        return
    except paramiko.BadAuthenticationType as exc:
        allowed = list(exc.allowed_types)
    except paramiko.AuthenticationException:
        allowed = ["password", "keyboard-interactive"]
    log.info("SFTP server offers authentication methods: %s", ", ".join(allowed) or "(none)")

    def answer_prompts(title, instructions, prompts):
        if prompts:
            log.debug("keyboard-interactive prompts: %s", [p[0] for p in prompts])
        return [SFTP_PASSWORD for _ in prompts]

    errors = []
    if "password" in allowed:
        try:
            # fallback=False: keyboard-interactive is tried explicitly below.
            transport.auth_password(SFTP_USER, SFTP_PASSWORD, fallback=False)
            log.info("Authenticated as %s using 'password'", SFTP_USER)
            return
        except paramiko.AuthenticationException as exc:
            errors.append("password: %s" % exc)
    if "keyboard-interactive" in allowed:
        try:
            transport.auth_interactive(SFTP_USER, answer_prompts)
            log.info("Authenticated as %s using 'keyboard-interactive'", SFTP_USER)
            return
        except paramiko.AuthenticationException as exc:
            errors.append("keyboard-interactive: %s" % exc)

    if not errors:
        raise paramiko.AuthenticationException(
            "Server does not offer password login for %s (offered: %s)"
            % (SFTP_USER, ", ".join(allowed))
        )
    raise paramiko.AuthenticationException(
        "Login rejected for user %s (%s). Check SFTP_USER / SFTP_PASSWORD."
        % (SFTP_USER, "; ".join(errors))
    )


def connect_sftp() -> Tuple[paramiko.Transport, paramiko.SFTPClient]:
    """Open an SSH connection and return (transport, sftp_client)."""
    if not SFTP_PASSWORD or SFTP_PASSWORD == PLACEHOLDER_SFTP_PASSWORD:
        raise JobError(
            "SFTP_PASSWORD is not set (still the placeholder). Export it first, e.g. "
            "export SFTP_PASSWORD='your-password'  (use single quotes if it contains $ ! or `)",
            EXIT_GENERAL_ERROR,
        )

    log.info("Connecting to SFTP %s@%s:%d", SFTP_USER, SFTP_HOST, SFTP_PORT)
    sock = socket.create_connection((SFTP_HOST, SFTP_PORT), timeout=SFTP_TIMEOUT_SECONDS)
    transport = paramiko.Transport(sock)
    try:
        transport.banner_timeout = SFTP_TIMEOUT_SECONDS
        transport.auth_timeout = SFTP_TIMEOUT_SECONDS

        # Equivalent of: sftp -o HostKeyAlgorithms=+ssh-rsa
        # Append the extra algorithms to paramiko's defaults (never remove any).
        options = transport.get_security_options()
        key_types = list(options.key_types)
        for algo in SFTP_EXTRA_HOST_KEY_ALGORITHMS:
            if algo not in key_types:
                key_types.append(algo)
        options.key_types = tuple(key_types)
        log.debug("Accepted host key algorithms: %s", ", ".join(key_types))

        transport.start_client(timeout=SFTP_TIMEOUT_SECONDS)
        server_key = transport.get_remote_server_key()
        log.info("SFTP server host key: %s %s", server_key.get_name(), server_key.fingerprint)
        _verify_host_key(server_key)

        _authenticate(transport)

        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            raise paramiko.SSHException("Server refused to open the SFTP subsystem")
        sftp.get_channel().settimeout(SFTP_TIMEOUT_SECONDS)
    except Exception:
        transport.close()
        raise
    log.info("SFTP connection established")
    return transport, sftp


def list_json_files(sftp: paramiko.SFTPClient, remote_dir: str) -> List[str]:
    """Return names of regular ``*.json`` files in ``remote_dir``."""
    log.info("Listing %s*%s", remote_dir.rstrip("/") + "/", JSON_EXTENSION)
    names = [
        entry.filename
        for entry in sftp.listdir_attr(remote_dir)
        if stat.S_ISREG(entry.st_mode or 0)
        and entry.filename.lower().endswith(JSON_EXTENSION)
    ]
    if SORT_FILES_BY_NAME:
        names.sort()
    log.info("Found %d JSON file(s) in %s", len(names), remote_dir)
    for name in names:
        log.debug("  - %s", name)
    return names


def download_and_parse_json_files(
    sftp: paramiko.SFTPClient, remote_dir: str, filenames: List[str]
) -> Tuple[List[Any], List[str]]:
    """
    Download and parse each file.

    Returns ``(parsed_objects, successfully_parsed_filenames)`` where element
    ``i`` of the first list is the full content of the file at index ``i`` of
    the second list.
    """
    parsed: List[Any] = []
    ok_files: List[str] = []
    for name in filenames:
        path = posixpath.join(remote_dir, name)
        try:
            with sftp.open(path, "rb") as fh:
                fh.prefetch()
                raw = fh.read()
        except (IOError, OSError, paramiko.SSHException) as exc:
            raise JobError("Failed to download %s: %s" % (path, exc), EXIT_SFTP_ERROR)

        try:
            obj = json.loads(raw.decode(JSON_FILE_ENCODING))
        except (UnicodeDecodeError, ValueError) as exc:
            if SKIP_INVALID_JSON_FILES:
                log.error("Skipping invalid JSON file %s: %s", path, exc)
                continue
            raise JobError("Invalid JSON in %s: %s" % (path, exc), EXIT_JSON_ERROR)

        parsed.append(obj)
        ok_files.append(name)
        log.debug("Parsed %s (%d bytes)", path, len(raw))

    log.info("Parsed %d of %d JSON file(s)", len(ok_files), len(filenames))
    return parsed, ok_files


def move_processed_files(
    sftp: paramiko.SFTPClient, remote_dir: str, filenames: List[str], processed_dir: str
) -> List[str]:
    """Move files into ``processed_dir``. Returns the list of files that failed."""
    ensure_remote_dir(sftp, processed_dir)
    failed: List[str] = []
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")

    for name in filenames:
        src = posixpath.join(remote_dir, name)
        dst = posixpath.join(processed_dir, name)
        if remote_exists(sftp, dst):
            base, ext = posixpath.splitext(name)
            dst = posixpath.join(processed_dir, "%s_%s_%s%s" % (base, stamp, uuid.uuid4().hex[:6], ext))
            log.warning("%s already exists in %s, using %s", name, processed_dir, dst)
        try:
            sftp.rename(src, dst)
            log.info("Moved %s -> %s", src, dst)
        except (IOError, OSError) as rename_exc:
            # Fallback for servers without rename support: copy + delete.
            log.warning("Rename of %s failed (%s), falling back to copy + delete", src, rename_exc)
            try:
                with sftp.open(src, "rb") as reader, sftp.open(dst, "wb") as writer:
                    reader.prefetch()
                    while True:
                        chunk = reader.read(65536)
                        if not chunk:
                            break
                        writer.write(chunk)
                if sftp.stat(dst).st_size != sftp.stat(src).st_size:
                    raise IOError("size mismatch after copy")
                sftp.remove(src)
                log.info("Copied and removed %s -> %s", src, dst)
            except (IOError, OSError) as copy_exc:
                log.error("Failed to move %s to %s: %s", src, dst, copy_exc)
                failed.append(name)

    log.info("Moved %d of %d file(s) to %s", len(filenames) - len(failed), len(filenames), processed_dir)
    return failed


# =============================================================================
# MySQL
# =============================================================================
def connect_mysql():
    log.info("Connecting to MySQL %s@%s:%d/%s", MYSQL_USER, MYSQL_HOST, MYSQL_PORT, MYSQL_DATABASE)
    conn = mysql.connector.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        charset="utf8mb4",
        collation="utf8mb4_unicode_ci",
        connection_timeout=MYSQL_CONNECT_TIMEOUT_SECONDS,
        autocommit=False,
    )
    log.info("MySQL connection established (server %s)", conn.get_server_info())
    return conn


def save_to_mysql(json_array_str: str, db_conn) -> Tuple[int, str]:
    """Insert one inbox row. Returns ``(inserted_row_id, externalKey)``."""
    now = datetime.now().replace(microsecond=0)
    external_key = generate_external_key(now)
    params = (
        json_array_str,                        # fileContent
        INBOX_STATUS_NEW,                      # status
        now,                                   # inboxCreationDateTime
        IMPORT_SOURCE,                         # importSource
        now,                                   # externalKey
        SYSTEM_VERSION_NUMBER,                 # systemVersionNumber
        now,                                   # lastImportDateTime
        FILE_ID,                               # file
        EXTERNAL_APPLICATION_INSTANCE,         # externalApplicationInstance
        EXTERNAL_APP_INSTANCES_TO_LINK_TYPE,   # externalApplicationInstancesToLinkType
        creation_date_in_external_system(),    # creationDateInExternalSystem
    )
    cursor = db_conn.cursor()
    try:
        cursor.execute(INSERT_SQL, params)
        db_conn.commit()
        row_id = cursor.lastrowid
    except Exception:
        db_conn.rollback()
        raise
    finally:
        cursor.close()
    log.info(
        "Inserted row id=%s externalKey=%s (%d bytes of fileContent)",
        row_id, external_key, len(json_array_str.encode("utf-8")),
    )
    return row_id, external_key


# =============================================================================
# Orchestration
# =============================================================================
def test_connection() -> int:
    """Only connect to SFTP and list the JSON files - no MySQL, nothing moved."""
    transport, sftp = connect_sftp()
    try:
        list_json_files(sftp, SFTP_REMOTE_DIR)
    finally:
        sftp.close()
        transport.close()
    log.info("SFTP connection test OK")
    return EXIT_OK


def run() -> int:
    transport: Optional[paramiko.Transport] = None
    sftp: Optional[paramiko.SFTPClient] = None
    db_conn = None
    try:
        # 1. Connect to SFTP
        try:
            transport, sftp = connect_sftp()
        except (paramiko.SSHException, OSError) as exc:
            raise JobError("SFTP connection failed: %s" % exc, EXIT_SFTP_ERROR)

        # 2. List JSON files
        try:
            filenames = list_json_files(sftp, SFTP_REMOTE_DIR)
        except (IOError, OSError) as exc:
            raise JobError("Cannot list %s: %s" % (SFTP_REMOTE_DIR, exc), EXIT_SFTP_ERROR)
        if not filenames:
            log.info("Nothing to do - no JSON files found")
            return EXIT_OK

        # 3. Download and parse
        json_objects, processed_files = download_and_parse_json_files(sftp, SFTP_REMOTE_DIR, filenames)
        if not json_objects:
            log.warning("No valid JSON files to import")
            return EXIT_JSON_ERROR

        # 4. Serialize the zero-based list: [content_of_file_0, content_of_file_1, ...]
        json_array_str = json.dumps(json_objects, ensure_ascii=False)

        # 5. Connect to MySQL and insert
        try:
            db_conn = connect_mysql()
            save_to_mysql(json_array_str, db_conn)
        except MySQLError as exc:
            raise JobError(
                "MySQL error - files were NOT moved: %s" % exc, EXIT_MYSQL_ERROR
            )

        # 6. Move processed files
        try:
            failed = move_processed_files(sftp, SFTP_REMOTE_DIR, processed_files, SFTP_PROCESSED_DIR)
        except (IOError, OSError) as exc:
            raise JobError(
                "Data was stored in MySQL but moving files failed: %s. "
                "These files will be imported again on the next run unless moved manually." % exc,
                EXIT_MOVE_ERROR,
            )
        if failed:
            log.error(
                "Data was stored in MySQL but %d file(s) could not be moved: %s. "
                "They will be imported again on the next run unless moved manually.",
                len(failed), ", ".join(failed),
            )
            return EXIT_MOVE_ERROR

        log.info("Import finished successfully: %d file(s) imported", len(processed_files))
        return EXIT_OK

    finally:
        # 7. Close connections
        if db_conn is not None:
            try:
                db_conn.close()
                log.info("MySQL connection closed")
            except Exception:  # pragma: no cover - best effort
                log.debug("Error closing MySQL connection", exc_info=True)
        if sftp is not None:
            sftp.close()
        if transport is not None:
            transport.close()
            log.info("SFTP connection closed")


def main() -> int:
    parser = argparse.ArgumentParser(description="Import SFTP JSON files into MySQL.")
    parser.add_argument(
        "--test-connection",
        action="store_true",
        help="only log in to SFTP and list the JSON files (no MySQL, nothing is moved)",
    )
    args = parser.parse_args()

    setup_logging()
    log.info("=== SFTP JSON -> MySQL import started ===")
    lock = None
    try:
        if args.test_connection:
            code = test_connection()
        else:
            lock = acquire_lock(LOCK_FILE)
            code = run()
    except JobError as exc:
        log.error("%s", exc)
        code = exc.exit_code
    except (paramiko.SSHException, OSError) as exc:
        log.error("SFTP connection failed: %s", exc)
        code = EXIT_SFTP_ERROR
    except Exception:
        log.exception("Unexpected error")
        code = EXIT_GENERAL_ERROR
    finally:
        if lock is not None:
            lock.close()
    log.info("=== Finished with exit code %d ===", code)
    return code


if __name__ == "__main__":
    sys.exit(main())
