#!/usr/bin/env python3
import logging
import sqlite3
import subprocess
import sys

import requests
from cryptography import x509
from cryptography.x509 import PrecertPoison
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def prepare_logger(logger: logging.Logger):
    """
    Disable logging to console if stdin is not a tty
    :param logger: a logger
    :return: None
    """
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug

    # create formatter
    formatter = logging.Formatter('%(asctime)s: %(message)s')

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if not sys.stdin.isatty():
        logger.setLevel(logging.WARNING)


class CertStorage:
    """
    Stores certificates in a sqlite DB
    """

    def __init__(self):
        """
        Init DB-Connection and create table if not exists
        """
        self.logger = logging.getLogger("cert-storage")
        prepare_logger(self.logger)

        self.conn = sqlite3.connect('check-certs.sqlite')
        self.c = self.conn.cursor()
        # init DB
        try:
            self.c.execute(
                "create table certs (id text, serial text, domains text, valid_from timestamp, valid_until timestamp)")
        except sqlite3.OperationalError:
            pass

    def is_id_known(self, cert_id):
        """
        Check if a cert id is already known
        :param cert_id: The crt.sh id
        :return: True, if the id is known
        """
        self.c.execute("SELECT serial FROM certs where id = ?", [cert_id])
        known_id = self.c.fetchone()
        if known_id is not None:
            return True
        return False

    def save_cert(self, cert_id: str, domains: str, pem: bytes):
        """
        Save a cert to the DB
        :param cert_id: The crt.sh id
        :param domains: The domain-names as given by crt.sh
        :param pem: The PEM-encoded cert
        :return: True, if the cert is new
        """
        cert = x509.load_pem_x509_certificate(pem)
        serial = str(cert.serial_number)
        valid_from = cert.not_valid_before
        valid_until = cert.not_valid_after
        try:
            is_pre = cert.extensions.get_extension_for_class(x509.PrecertPoison)
            if is_pre.value == PrecertPoison():
                self.logger.debug(f"remember precert {cert_id}: {domains}")
                self.c.execute("INSERT INTO certs VALUES(?, ?, ?, ?, ?)", [cert_id, serial, domains, None, None])
                self.conn.commit()
        except x509.extensions.ExtensionNotFound:
            pass

        self.c.execute('SELECT domains FROM certs WHERE id=? AND serial=?', [cert_id, serial])
        if len(self.c.fetchall()) > 0:
            self.logger.debug(f"debug: serial: {serial} already known for {domains} with id: {cert_id}")
            return False

        self.logger.info(f"remember cert {cert_id}: {domains}")
        self.c.execute("INSERT INTO certs VALUES(?, ?, ?, ?, ?)", [cert_id, serial, domains, valid_from, valid_until])
        self.conn.commit()
        return True


class CrtSh:
    """
    Query crt.sh for certificates
    """
    def __init__(self):
        """
        Init a http session with a retry adapter
        """
        self.logger = logging.getLogger("crt_sh")
        prepare_logger(self.logger)

        self.session = requests.Session()
        retry = Retry(status=10, status_forcelist=[429], backoff_factor=0.5, respect_retry_after_header=True)
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('https://', adapter)

    def query_domains(self, domains: str):
        """
        Query crt.sh for a list of domains, matching the given query
        :param domains: list of domains, separated by", "to query crt.sh
        :return: a list of dicts with the results
        """
        self.logger.debug(f"loading {domains} from crt.sh")
        payload = {'Identity': domains, 'exclude': 'expired', 'output': 'json', 'match': 'ILIKE'}
        r = self.session.get('https://crt.sh/', params=payload)
        r.raise_for_status()
        return r.json()

    def load_cert_for_id(self, cert_id: str) -> bytes:
        """
        Load a single cert from crt.sh
        :param cert_id: The crt.sh id
        :return: the PEM-encoded cert as bytes
        """
        payload = {'d': cert_id}
        r = self.session.get('https://crt.sh/', params=payload)
        r.raise_for_status()
        pem = r.content
        return pem


def check_domains(domains_to_check: list[str]):
    """
    Check a list of domains for new certificates
    :param domains_to_check:
    :return:
    """
    logger = logging.getLogger("check-certs")
    prepare_logger(logger)

    crtsh = CrtSh()
    cert_store = CertStorage()
    for item in crtsh.query_domains(" OR ".join(domains_to_check)):
        cert_id = str(item['id'])
        domains = item['name_value'].strip().replace("\n", ",")

        if cert_store.is_id_known(cert_id):
            logger.debug(f"cert known {cert_id}: {domains}")
            continue

        try:
            logger.debug(f"loading cert {cert_id}: {domains}")
            pem = crtsh.load_cert_for_id(cert_id)
            if cert_store.save_cert(cert_id, domains, pem):
                # print(f"debug: cert {id}: {domains} is new")
                text = subprocess.run(["openssl", "x509", "-text", "-noout"],
                                      input=str(pem.decode('utf-8')), text=True, check=True,
                                      capture_output=True, timeout=5).stdout
                logger.warning(f"New cert '{domains}' for a monitored domain detected!\nIssued cert can be found at "
                               f"https://crt.sh/?id={cert_id}\n\n\n{text}")
        except Exception as e:
            logger.warning(f"failed to fetch cert {cert_id}: {domains}: {e}")
            continue


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: check-certs.py [domain1] [domain2] ...\n"
              "Using default domains", file=sys.stderr)
        check_domains(["wolfgang-jung.net", "wolle.dev"])
    else:
        check_domains(sys.argv[1:])
