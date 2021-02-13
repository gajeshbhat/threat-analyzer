import requests
import json
import logging
import arrow
from datetime import datetime
import time
from pprint import pprint

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

    def get_report(self):
        """
        Reads the given file for Hashes and Scan's each Hash on VirusTotal's Public API
        and returns a report_object list.
        :return report_object list:
        """
        self.hash_list = self._read_file()
        report_objs = list()

        for hash_val in self.hash_list:
            # TODO Better timeout handling and Redis Caching
            scan_resp = self._scan_hash(hash_val)
            if self.is_rate_limit(scan_resp):
                time.sleep(60)  # Sleep for a minute. 1 Minute - 4 Requests and try again
                scan_resp = self._scan_hash(hash_val)
                # If limited even after 1 minute. Day quota exceeded.
                # TODO: Multiple user request is not considered for above code.
                #  This time has to take into account other users making requests.
                #  A Processing Queue for requests is ideal.
                if self.is_rate_limit(scan_resp) is True:
                    # logging.info(f"Rate Limit Exceeded at for hash {hash_val} at {datetime.now()}\n")
                    continue
            hash_report = self.get_report_obj(hash_val, scan_resp)
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
            # Log an Unknown Key or other error
            # logging.info(f"Unknown key in object {report_obj} found at time {datetime.now()}\n")
            pass
        return report_obj

    def _scan_hash(self, hash_val):
        scan_url = str(self.SCAN_API_URL + hash_val)
        auth_header = {'x-apikey': self.api_key}

        try:
            scan_request = requests.get(url=scan_url, headers=auth_header)
        except requests.exceptions.RequestException as request_exceptions:
            # Log the traceback
            logging.error(f"The following Exception(s) at time {datetime.now()}\n" + request_exceptions.__traceback__)
            pass

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
                    hash_list.append(str(each_line.strip().decode('utf-8')))
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

# if __name__ == '__main__':
#     # TODO : Calculate ETA
#     # TODO: Deploy to Heroku
#     # TODO: Write Tests
#     # TODO : Implement @LRU over Flask APP
