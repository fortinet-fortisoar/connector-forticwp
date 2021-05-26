#!/usr/bin/env python
"""
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import requests
import logging
import arrow
import logging.handlers
import socket
from time import gmtime, strftime
import jmespath
from requests_toolbelt.utils import dump


def csv_to_array(input_arg):
    ''' Prepare POSTs payloads'''
    
    if not input_arg:
        return []
    elif ' ' in input_arg:
        input_arg = input_arg.replace(' ','')      

    if ',' in input_arg:
        return input_arg.split(',')
    else:
        return [input_arg]

class FortiCwpCS(object):
    ''' Main API Client Class '''

    def __init__(self,
                 base_url,                 
                 forticwp_credentials,
                 verify_ssl=False,
                 logger=None
                 ):
        self.forticwp_logging = self.set_logger(logger)
        self.forticwp_credentials = "Basic " + forticwp_credentials
        self.base_url = base_url + '/api/v1'
        self.verify_ssl = self.set_verify_ssl(verify_ssl)
        self.token_expires_at = 0
        self.request_timeout = 20
        self.company_id = ""
        self.role_id = ""
        self.company_name = ""
        self.headers = {
            'user-agent': 'autobot',
            'Authorization': self.forticwp_credentials
        }
        self.login()
                

    def set_logger(self, logger):
        if logger is None:
            logging.basicConfig(level=logging.DEBUG)
            new_logger = logging.getLogger('API_Logger')
            return new_logger
        else:
            return logger

    def set_verify_ssl(self, ssl_status):
        if isinstance(ssl_status,str):
            ssl_status.lower()
        if ssl_status in ["true", True]:
            return True
        elif ssl_status in ["false", False]:
            return False
        else:
            return True


    def login(self):
        ''' Fetches bearer access token'''

        try:
            response = self.make_rest_call('/auth/credentials/token/',
                                          data={"grant_type": "client_credentials"},
                                          method='POST'
                                          )
            if response['Status'] == 'Success':
                self.headers['Authorization'] = 'Bearer ' + response['data']['access_token']
                self.headers.update({'Content-Type' : 'application/json'})
                self.token_expires_at = response['data']['expires']
            
            else:
                self.forticwp_logging.exception('Authentication Failed {}'.format(response['data']))
                return 'Authentication Failed {}'.format(response['data'])

            resource_map = self.get_resource_map()
            self.role_id = resource_map['data'][0]['roleId']
            self.company_id = resource_map['data'][0]['companyMapSet'][0]['companyId']
            self.company_name = resource_map['data'][0]['companyMapSet'][0]['companyName']
            self.forticwp_logging.info('Authentication successful. it will be valid until: {0}\n{1}\n'.format(self.token_expires_at,self.company_name))

        except Exception:
            self.forticwp_logging.exception("Authentication Failed")
            raise

            
    def make_rest_call(self, endpoint, params=None, data=None, json=None, method='GET'):
        '''make_rest_call'''

        url = '{0}{1}'.format(self.base_url, endpoint)
        self.forticwp_logging.debug('\nRequest: URL {}\nHeaders:{}'.format(url,self.headers))
        try:
            response = requests.request(method,
                                        url,
                                        json=json,
                                        data=data,
                                        headers=self.headers,
                                        params=params,
                                        timeout=self.request_timeout,
                                        verify=self.verify_ssl,                                        
                                        )
            self.forticwp_logging.debug('REQUESTS_DUMP:\n{}'.format(dump.dump_all(response).decode('utf-8')))

            if response.status_code in [200,201]:
                return {'data':response.json(),'Status':'Success'}
            else:
                self.forticwp_logging.exception({"data": response.content,'Status':'Failed with Status Code: '+str(response.status_code)})
                return {"data": response.content,'Status':'Failed with Status Code: '+str(response.status_code)}

        except Exception:
            self.forticwp_logging.exception("Request Failed")
            raise


    def get_account_severity_level(self):
        '''Get user account details'''

        self.headers.update({'companyId' : str(self.company_id)})
        return self.make_rest_call('/dashboard/cloud/account/list')

    def get_account_role(self):
        '''Get user account details'''

        self.headers.update({'roleId' : str(self.role_id)})
        return self.make_rest_call('/account/role')

    def get_alert_severities(self):
        '''Get alert severities from FortiCWP'''

        return self.make_rest_call('/severity')

    def get_resource_map(self):
        '''Get the user and account basic information from FortiCWP'''

        return self.make_rest_call('/resourceURLMap')
      
    def get_alert_by_filter(self, start_time, end_time, skip, limit, alert_id='', alert_user='', severity='' ,alert_state=''):
        '''Get cloud service alert details.'''

        self.headers.update({'companyId' : str(self.company_id)})
        
        payload = {
        'startTime': start_time,
        'endTime': end_time,
        'id':alert_id,
        'user': csv_to_array(alert_user),
        'activity':[],
        'objectIdList':[],
        'objectName':'',
        'objectId':'',
        'severity': csv_to_array(severity),
        'status':[],
        'city':[],
        'idList':[],
        'alertType':[],
        'alertState': csv_to_array(alert_state),
        'policyCodeList':[],
        'policyCategories':[],
        'serviceList':[],
        'accountID':[],
        'countryList':[],
        'activityType':[],
        'asc':'',
        'desc':'',
        'skip':skip,
        'limit':limit
        }       
        
        return self.make_rest_call('/alert/list',
                                  method='POST',
                                  json=payload
                                  )
