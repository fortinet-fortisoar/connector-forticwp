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
        logger.exception('{0}'.format(e))
        raise ConnectorError('{0}'.format(e))


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
        if _operation == 'get_resource_map':
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


operations = {
    "get_resource_map": _get_call,
    "get_resource_list": get_resource_list,
    "get_resource_details": get_resource_details,
    "get_finding_list": get_finding_list

}
