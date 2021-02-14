import requests
import json
import redis
import logging
import arrow
import re
from datetime import datetime, timedelta
import time

# logging.basicConfig(filename='logs.txt',
#                     filemode='a',
#                     format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
#                     datefmt='%H:%M:%S',)

# TODO: Put the key in Environment Variable
API_KEY = '3b6d7e70adaf2d0c5f844d95c5c95ac0026a7400f85dfb1e2bd760907decff3a'


class VtScanAPI:
    SCAN_API_URL = str("https://www.virustotal.com/api/v3/files/")

    def __init__(self, api_key, file_path):
        if not isinstance(api_key, str):
            raise ValueError('API key must be a string.')

        if not isinstance(file_path, str):
            raise ValueError('File path must be a string.')

        self.api_key = api_key
        self.file_path = file_path
        self.hash_list = list()

    def get_report(self, redis_client: redis.Redis):
        """
        Reads the given file for Hashes and Scan's each Hash on VirusTotal's Public API
        and returns a report_object list.
        :return report_object list:
        """
        self.hash_list = self._read_file()
        report_objs = list()
        for hash_val in self.hash_list:
            if redis_client.exists(hash_val):
                hash_report = self._get_hash_from_cache(hash_val, redis_client)
                print("Cache used! Yay!")
                report_objs.append(hash_report)
                continue

            scan_resp = self._scan_hash(hash_val)

            if self.is_rate_limit(scan_resp):
                time.sleep(60)
                scan_resp = self._scan_hash(hash_val)
                if self.is_rate_limit(scan_resp) is True:
                    # logging.info(f"Rate Limit Exceeded at for hash {hash_val} at {datetime.now()}\n")
                    continue
            hash_report = self.get_report_obj(hash_val, scan_resp)

            # Store in Cache if and only if scan date is very recent.
            if hash_report['scan_date'] != 'N/A' and self._report_less_day(hash_report['scan_date']):
                self._set_hash_to_cache(hash_val, hash_report, redis_client)

            report_objs.append(hash_report)

        return report_objs

    def get_report_obj(self, hash_val, response_obj):
        report_obj = {
            'hash_value': hash_val,
        }
        if 'error' in response_obj:
            if 'NotFoundError' == response_obj['error']['code']:
                report_obj['forti_detect_names'] = response_obj['error']['message']
                report_obj['num_of_detections'] = 'N/A'
                report_obj['scan_date'] = 'N/A'
        elif 'data' in response_obj:
            analysis_data = response_obj['data']['attributes']['last_analysis_results']

            if 'Fortinet' in analysis_data and analysis_data['Fortinet']['result'] is not None:
                report_obj['forti_detect_names'] = analysis_data['Fortinet']['result']
            else:
                report_obj['forti_detect_names'] = 'No detection for Fortinet Engine'

            report_obj['num_of_detections'] = len(analysis_data)
            report_obj['scan_date'] = self._get_local_time(response_obj['data']['attributes']['last_analysis_date'])
        else:
            # logging.info(f"Unknown key in object {report_obj} found at time {datetime.now()}\n")
            pass
        return report_obj

    def _scan_hash(self, hash_val):
        scan_url = str(self.SCAN_API_URL + hash_val)
        auth_header = {'x-apikey': self.api_key}

        try:
            scan_request = requests.get(url=scan_url, headers=auth_header)
        except requests.exceptions.RequestException as request_exceptions:
            logging.error(f"The following Exception(s) at time {datetime.now()}\n" + request_exceptions.__traceback__)

        scan_response = scan_request.json()
        return scan_response

    def _read_file(self):
        """
        Reads a file and returns a python list of lines separated by newline.
        :return list of lines:
        """
        hash_list = list()
        if len(self.file_path) == 0:
            raise ValueError("Empty string cannot be a file path!")
        else:
            with open(self.file_path, "rb") as file_pointer:
                for each_line in file_pointer:
                    line_data = str(each_line.strip().decode('utf-8'))

                    # MD5 and SHA-256 Regex check
                    md5_check = len(re.findall(r"([a-fA-F\d]{32})", line_data)) > 0
                    sha_256_check = len(re.findall(r"\b[A-Fa-f0-9]{64}\b",line_data)) > 0

                    is_req_hash = md5_check or sha_256_check
                    if each_line != "" and is_req_hash:
                        hash_list.append(line_data)
            file_pointer.close()
        return hash_list

    def _get_local_time(self, param):
        utc_datetime = arrow.get(param)
        return utc_datetime.to('local').format()

    def _report_less_day(self, param):
        current_time = arrow.get(str(datetime.now())).to('local')
        given_time = arrow.get(param).to('local')
        time_diff = current_time - given_time
        if time_diff.days <= 1:
            return True
        return False

    def is_rate_limit(self, scan_resp):
        return 'error' in scan_resp and scan_resp['error']['code'] == 'QuotaExceededError'

    def _get_serialized_json(self, data):
        return json.dumps(data)

    def _get_hash_from_cache(self, key, client: redis.Redis) -> str:
        """Get data from redis."""
        hash_scan_res = json.loads(client.get(key).decode('utf-8'))
        return hash_scan_res

    def _set_hash_to_cache(self, key, value, client: redis.Redis) -> bool:
        """Set data to redis."""
        state = client.setex(key, timedelta(days=1), value=json.dumps(value))
        return state

# if __name__ == '__main__':
#     # TODO: Deploy to Heroku or AWS
#     # TODO: Write Tests
