""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import arrow
from connectors.core.connector import get_logger, ConnectorError
from .forticnp_api import FortiCnpCS
from .constants import *

logger = get_logger('fortinet-Forticnp')


def FortiCNP_init(config):
    try:
        if config.get('server_url')[:8] == 'https://':
            server_url = config.get('server_url')
        else:
            server_url = 'https://{}'.format(config.get('server_url'))

        FortiCNP = FortiCnpCS(
            base_url=server_url,
            forticwp_credentials=config.get('api_key'),
            verify_ssl=config.get('verify_ssl'),
            logger=logger
        )
        return FortiCNP
    except Exception as e:
        logger.exception("Failed to connect: {}".format(e))
        raise ConnectorError("Failed to connect: {}".format(e))


def check_health(config):
    try:
        forticwp = FortiCNP_init(config)
        return True
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def _get_call(config, params):
    ''' _get_call '''
    try:
        forticwp = FortiCNP_init(config)
        _operation = params.get("operation")
        if _operation == 'get_account_severity_level':
            return forticwp.get_account_severity_level()
        elif _operation == 'get_alert_severities':
            return forticwp.get_alert_severities()
        elif _operation == 'get_resource_map':
            return forticwp.get_resource_map()
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def get_resource_list(config, params):
    forticnp = FortiCNP_init(config)
    forticnp.headers.update({'companyId': str(forticnp.company_id), 'roleId': str(forticnp.role_id)})
    body = {
        "filter": {
            "resourceType": {
                "option": params.get('filter')
            },
        },
        "skip": params.get('skip'),
        "limit": params.get('limit'),
        "status": params.get('status'),
        "orderBy": PARAM_MAPPING_DICT.get(params.get('orderBy'), ''),
        "orderDirection": PARAM_MAPPING_DICT.get(params.get('orderDirection'), '')
    }
    param_dict = {k: v for k, v in body.items() if v is not None and v != '' and v != {} and v != []}
    return forticnp.make_rest_call(GET_RESOURCE_LIST, method='POST', json=param_dict)


def get_resource_details(config, params):
    forticnp = FortiCNP_init(config)
    forticnp.headers.update({'companyId': str(forticnp.company_id), 'roleId': str(forticnp.role_id),
                             'rid': str(params.get('resourceid'))})
    return forticnp.make_rest_call(GET_RESOURCE_DETAILS, method='GET')


def get_events(config, params):
    forticnp = FortiCNP_init(config)
    forticnp.headers.update({'companyId': str(forticnp.company_id), 'roleId': str(forticnp.role_id)})
    return forticnp.make_rest_call(GET_EVENTS, method='GET')


def get_policy_violation(config, params):
    forticnp = FortiCNP_init(config)
    forticnp.headers.update({'companyId': str(forticnp.company_id), 'roleId': str(forticnp.role_id),
                             'starttime': str(round(arrow.get(params.get('starttime')).timestamp()) * 1000),
                             'endtime': str(round(arrow.get(params.get('endtime')).timestamp()) * 1000)})
    return forticnp.make_rest_call(GET_POLICY_VIOLATION, method='GET')


def get_document_violation(config, params):
    forticnp = FortiCNP_init(config)
    forticnp.headers.update({'companyId': str(forticnp.company_id), 'roleId': str(forticnp.role_id),
                             'fileId': params.get('fileId')})
    return forticnp.make_rest_call(GET_DOCUMENT_VIOLATION, method='POST')


def get_finding_list(config, params):
    forticnp = FortiCNP_init(config)
    forticnp.headers.update({'companyId': str(forticnp.company_id), 'roleId': str(forticnp.role_id)})
    body = {
        'skip': params.get('skip') if params.get('skip') else 0,
        'limit': params.get('limit') if params.get('limit') else 100,
        'objectId': params.get('objectId'),
        'startTime': str(round(arrow.get(params.get('startTime')).timestamp()) * 1000),
        'endTime': str(round(arrow.get(params.get('endTime')).timestamp()) * 1000)
    }
    param_dict = {k: v for k, v in body.items() if v is not None and v != '' and v != {} and v != []}
    return forticnp.make_rest_call(GET_FINDING_LIST, method='POST', json=param_dict)


def _post_call(config, params):
    '''POST'''
    try:
        forticwp = FortiCNP_init(config)
        _operation = params.get("operation")
        start_time = params.get("start_time")
        end_time = params.get("end_time")
        alert_id = params.get("alert_id")
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
            return {'data': 'Invalid Start Time or End Time', 'Status': 'Failure'}
        if start_time > end_time:
            return {'data': 'Start Time cannot be more recent than End Time', 'Status': 'Failure'}
        elif _operation == 'get_alert_by_filter':
            return forticwp.get_alert_by_filter(start_time, end_time, skip, limit, alert_id, alert_user, severity,
                                                alert_state)

    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


operations = {
    "get_account_severity_level": _get_call,
    "get_alert_severities": _get_call,
    "get_resource_map": _get_call,
    "get_alert_by_filter": _post_call,
    "get_resource_list": get_resource_list,
    "get_resource_details": get_resource_details,
    "get_events": get_events,
    "get_policy_violation": get_policy_violation,
    "get_document_violation" : get_document_violation,
    "get_finding_list": get_finding_list

}
