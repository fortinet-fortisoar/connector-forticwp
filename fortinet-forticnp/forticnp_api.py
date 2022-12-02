""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
from requests_toolbelt.utils import dump
from connectors.core.connector import get_logger, ConnectorError
from .constants import *
logger = get_logger('fortinet-Forticnp')


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


class FortiCnpCS(object):
    ''' Main API Client Class '''

    def __init__(self,
                 base_url,                 
                 forticwp_credentials,
                 verify_ssl=False,
                 logger=None
                 ):
        self.forticwp_credentials = "Basic " + forticwp_credentials
        self.base_url = base_url
        self.verify_ssl = verify_ssl
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

    def login(self):
        ''' Fetches bearer access token'''

        try:
            response = self.make_rest_call(AUTH_API,
                                          data={"grant_type": "client_credentials"},
                                          method='POST'
                                          )
            if response.get('access_token'):
                self.headers['Authorization'] = 'Bearer ' + response.get('access_token')
                self.headers.update({'Content-Type': 'application/json'})
                self.token_expires_at = response.get('expires')
            
            else:
                logger.exception('Authentication Failed {0}'.format(response))
                raise 'Authentication Failed {0}'.format(response)

            resource_map = self.get_resource_map()
            self.role_id = resource_map[0]['roleId']
            self.company_id = resource_map[0]['companyMapSet'][0]['companyId']
            self.company_name = resource_map[0]['companyMapSet'][0]['companyName']
            logger.info('Authentication successful. it will be valid until: {0}\n{1}\n'.format(self.token_expires_at,self.company_name))

        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))
            
    def make_rest_call(self, endpoint, params=None, data=None, json=None, method='GET', login_flag=False):
        '''make_rest_call'''

        url = '{0}{1}'.format(self.base_url, endpoint)
        logger.debug('\nRequest: URL {0}\nHeaders:{1}'.format(url, self.headers))
        try:
            response = requests.request(method,
                                        url,
                                        json=json,
                                        data=data,
                                        headers=self.headers,
                                        params=params,
                                        timeout=self.request_timeout,
                                        verify=self.verify_ssl
                                        )
            logger.debug('REQUESTS_DUMP:\n{0}'.format(dump.dump_all(response).decode('utf-8')))

            if response.status_code in [200, 201]:
                if 'json' in response.headers.get('Content-Type'):
                    return response.json()
                else:
                    return response.content
            elif response.status_code == 401:
                raise ConnectorError('Invalid Credentials')
            else:
                logger.exception({"data": response.content, 'Status': 'Failed with Status Code: '+str(response.status_code)})
                raise ConnectorError('response = {0} and status code = {1}'.format(response.content, response.status_code))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def get_account_severity_level(self):

        self.headers.update({'companyId': str(self.company_id), 'roleId': str(self.role_id)})
        return self.make_rest_call(GET_ACCOUNT_SEVERITY_LEVEL)

    def get_alert_severities(self):
        self.headers.update({'companyId': str(self.company_id), 'roleId': str(self.role_id)})
        return self.make_rest_call(GET_ALERT_SEVERITY)

    def get_resource_map(self):
        '''Get the user and account basic information from FortiCWP'''
        return self.make_rest_call(GET_RESOURCE_MAP)
      
    def get_alert_by_filter(self, start_time, end_time, skip, limit, alert_id='', alert_user='', severity='', alert_state=''):
        '''Get cloud service alert details.'''

        self.headers.update({'companyId': str(self.company_id), 'roleId': str(self.role_id)})
        
        payload = {
        'startTime': start_time,
        'endTime': end_time,
        'id': alert_id,
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
        
        return self.make_rest_call(GET_ALERTS,
                                  method='POST',
                                  json=payload
                                  )
