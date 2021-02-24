import logging
import re
import os
import time
import requests
import arrow
import redis
import json
from datetime import datetime, timedelta

# Key's in Json Response Object
ERROR_KEY = "error"
NOT_FOUND_ERR = "NotFoundError"
CODE_KEY = "code"
FORTI_TAG = "forti_detect_names"
MESSAGE_KEY = "message"
NUM_DETECT_KEY = "num_of_detections"
SCAN_DATE_KEY = "scan_date"
DATA_KEY = "data"
ATTR_KEY = "attributes"
LAT_ANA_RES_KEY = "last_analysis_results"
LAT_ANA_DATE_KEY = "last_analysis_date"
RES_KEY = "result"
FORTI_NAME_KEY = "Fortinet"
QUOTA_ERROR_KEY = "QuotaExceededError"

# Strings
NOT_AVAIL = "N/A"
FORTINET_NA = "No detection for Fortinet Engine"

# REGEX
MD5_REGEX = "([a-fA-F\d]{32})"
SHA256_REGEX = "\b[A-Fa-f0-9]{64}\b"

API_KEY = os.environ.get('VT_API_KEY')


# Helper Methods

def is_rate_limit(scan_resp):
    """
    Returns True if the API Parses has hit the rate limit else False
    :param scan_resp:
    :return True or False:
    """
    return ERROR_KEY in scan_resp and scan_resp[ERROR_KEY][CODE_KEY] == QUOTA_ERROR_KEY


def get_cached_report(key, client: redis.Redis):
    """
    Retrives the cached report using Hash Value.
    :param key:
    :param client:
    :return scan_report:
    """
    scan_report = json.loads(client.get(key).decode('utf-8'))
    return scan_report


def set_report_cache(key, value, client: redis.Redis):
    """
    Set's the JSON Serialized report object as a value with Hash as key.
    :param key:
    :param value:
    :param client:
    :return:
    """
    client.setex(key, timedelta(days=1), value=json.dumps(value))


def get_local_time(utc_string):
    """
    Returns local time strings given UTC time
    :param utc_string:
    :return:
    """
    utc_datetime = arrow.get(utc_string)
    return utc_datetime.to('local').format()


def report_less_day(param):
    """
    Returns True if the given time is less than a day.
    :param param:
    :return:
    """
    current_time = arrow.get(str(datetime.now())).to('local')
    given_time = arrow.get(param).to('local')
    time_diff = current_time - given_time
    if time_diff.days <= 1:
        return True
    return False


def get_scan_report(hash_val, resp):
    """
    Takes a Scan Report response object and returns a scan report dictionary.
    :param hash_val:
    :param resp:
    :return report_obj:
    """
    scan_report = {
        'hash_value': hash_val,
    }

    if ERROR_KEY in resp:
        if NOT_FOUND_ERR == resp[ERROR_KEY][CODE_KEY]:
            scan_report[FORTI_TAG] = resp[ERROR_KEY][MESSAGE_KEY]
            scan_report[NUM_DETECT_KEY] = NOT_AVAIL
            scan_report[SCAN_DATE_KEY] = NOT_AVAIL
    else:
        analysis_data = resp[DATA_KEY][ATTR_KEY][LAT_ANA_RES_KEY]

        if FORTI_NAME_KEY in analysis_data and analysis_data[FORTI_NAME_KEY][RES_KEY] is not None:
            scan_report[FORTI_TAG] = analysis_data[FORTI_NAME_KEY][RES_KEY]
        else:
            scan_report[FORTI_TAG] = FORTINET_NA

        scan_report[NUM_DETECT_KEY] = len(analysis_data)
        report_utc_time = resp[DATA_KEY][ATTR_KEY][LAT_ANA_DATE_KEY]
        scan_report[SCAN_DATE_KEY] = get_local_time(report_utc_time)

    return scan_report


class VtScanAPI:
    """
    A wrapper class to Scan Md5 Hashes for threats using VirusTotal Public API.
    """
    SCAN_API_URL = str("https://www.virustotal.com/api/v3/files/")

    def __init__(self, api_key, file_path):
        """
        Initializes API Wrapper Object.
        :param api_key:
        :param file_path:
        """
        if not isinstance(api_key, str):
            raise ValueError('API key must be a string.')

        if not isinstance(file_path, str):
            raise ValueError('File path must be a string.')

        self.api_key = api_key
        self.file_path = file_path
        self.hashes = list()
        self.report = list()

    def get_file_report(self, redis_client: redis.Redis):
        """
        Parses the text file for Md5 and Sha256 and scans them for threats.
        Stores reports updated a day ago in cache.

        :param redis_client:
        :return scan_results:
        """
        hash_list = self._read_file()
        report_objs = list()

        for hash_val in hash_list:

            # Check for value in cache
            if redis_client.exists(hash_val):
                hash_report = get_cached_report(hash_val, redis_client)
                report_objs.append(hash_report)
                continue

            # Scan for Report
            scan_resp = self._scan_hash(hash_val)

            # If Request failed, Drop and Continue. Check the logs
            if scan_resp is None:
                continue

            # If Rate maxed out, wait.
            if is_rate_limit(scan_resp):
                time.sleep(60)
                scan_resp = self._scan_hash(hash_val)
                # Rate limit after wait, exhausted daily quota. Drop and Continue.
                if is_rate_limit(scan_resp):
                    continue

            # Get Report dict using the scan report response
            hash_report = get_scan_report(hash_val, scan_resp)

            # Store in cache if  scan date <= 1 day.
            hash_last_scan_date = hash_report['scan_date']
            if hash_last_scan_date != NOT_AVAIL and report_less_day(hash_last_scan_date):
                set_report_cache(hash_val, hash_report, redis_client)

            # Add to reports list
            report_objs.append(hash_report)

        self.report = report_objs
        return report_objs

    def _scan_hash(self, hash_val):
        """
        Scan's the Virtual total API and retrives the report for a file using its hash.
        :param hash_val: 
        :return scan_response:
        """
        # Prepare URL and Request
        scan_url = str(self.SCAN_API_URL + hash_val)
        auth_header = {'x-apikey': self.api_key}

        scan_response = None

        # Make Request and log exceptions
        try:
            scan_request = requests.get(url=scan_url, headers=auth_header)
            scan_response = scan_request.json()
        except requests.exceptions.RequestException as request_exceptions:
            logging.error(f"The following Exception(s) at time {datetime.now()}\n")
            logging.error(request_exceptions.__traceback__)

        return scan_response

    def _read_file(self):
        """
        Reads a file from self.file_path and returns a list of all the valid MD5 and SHA-256 hashes..
        :return list of valid md5 and sha-256 hashes:
        """
        hash_list = list()

        if len(self.file_path) == 0:
            raise ValueError("Empty string cannot be a file path!")
        else:
            with open(self.file_path, "rb") as file_pointer:

                for each_line in file_pointer:

                    line_data = str(each_line.strip().decode('utf-8'))

                    # MD5 and SHA-256 Regex check
                    md5_check = len(re.findall(rf"{MD5_REGEX}", line_data)) > 0
                    sha_256_check = len(re.findall(rf"{SHA256_REGEX}", line_data)) > 0

                    # Only check if the hash is MD5 or SHA-256 (According to Requirements)
                    is_req_hash = md5_check or sha_256_check
                    if each_line != "" and is_req_hash:
                        hash_list.append(line_data)

            # Close the file after reading
            file_pointer.close()

        self.hashes = hash_list
        return hash_list

    def __len__(self):
        return len(self.report)

    def __str__(self):
        return str(VtScanAPI.__doc__)


if __name__ == '__main__':
    pass
