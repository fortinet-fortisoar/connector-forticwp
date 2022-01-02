""" operations.py """

import logging
import arrow
from requests.models import Response
from integrations.crudhub import maybe_json_or_raise
from connectors.core.connector import get_logger, ConnectorError
from .forticwp_api import FortiCwpCS


logger = get_logger('fortinet-FortiCWP')
#logger.setLevel(logging.DEBUG)

def FortiCWP_init(config):
    try:
        if config.get('server_url')[:8] == 'https://':
            server_url = config.get('server_url')
        else:
            server_url = 'https://{}'.format(config.get('server_url'))             

        FortiCWP = FortiCwpCS(
        base_url=server_url, 
        forticwp_credentials = config.get('api_key'),
        verify_ssl = config.get('verify_ssl'),
        logger = logger
        )
        return FortiCWP
    except Exception as e:
        logger.exception("Failed to connect: {}".format(e))
        raise ConnectorError("Failed to connect: {}".format(e))

def check_health(config):
    try:
      forticwp = FortiCWP_init(config)
      response = forticwp.get_alert_severities()
      logger.info("Invoking check_health: {}".format(response['Status']))
      if response['Status'] == 'Success':
          return True
      else:
          logger.exception('{0}'.format(response))
          raise ConnectorError('{0}'.format(response))

    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))

def _get_call(config, params):
    ''' _get_call '''
    try:
        forticwp = FortiCWP_init(config)
        _operation = params.get("operation")
        if _operation == 'get_account_':# DUPLICATE TO REMOVE
            return forticwp.get_account_role()

        elif _operation == 'get_account_severity_level':
            return forticwp.get_account_severity_level()
        elif _operation == 'get_account_role':
            return forticwp.get_account_role()
        elif _operation == 'get_alert_severities':
            return forticwp.get_alert_severities()
        elif _operation == 'get_resource_map':
            return forticwp.get_resource_map()        


    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))

def _post_call(config, params):
    '''POST'''
    try:
        forticwp = FortiCWP_init(config)
        _operation = params.get("operation")
        start_time = params.get("start_time")
        end_time = params.get("end_time")
        alert_ids = params.get("alert_ids")
        alert_user = params.get("alert_user")
        severity = params.get("severity")
        alert_state = params.get("alert_state")
        skip = params.get("skip")
        limit = params.get("limit")
        if start_time:
            start_time = round(arrow.get(start_time).timestamp()) * 1000
        if end_time:
            end_time = round(arrow.get(end_time).timestamp()) * 1000
        if not isinstance(start_time, int) or not isinstance(end_time, int):
            return {'data':'Invalid Start Time or End Time','Status':'Failure'}
        if start_time > end_time:
            return {'data':'Start Time cannot be more recent than End Time','Status':'Failure'}          
        elif _operation == 'get_alert_by_filter':
            logger.error('START END TIME {} {}'.format(severity,type(severity)))
            return forticwp.get_alert_by_filter(start_time, end_time, skip, limit, alert_ids, alert_user, severity ,alert_state)
        
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))

operations = {  
    "get_account_severity_level": _get_call,
    "get_account_role": _get_call,  
    "get_alert_severities": _get_call,
    "get_resource_map": _get_call,
    "get_alert_by_filter": _post_call
}