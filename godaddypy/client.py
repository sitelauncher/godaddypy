import logging
import sys
from datetime import datetime

import requests

__all__ = ['Client']


class Client(object):
    """The GoDaddyPy Client.

    This client is used to connect to the GoDaddy API and to perform requests with said API.
    """

    def __init__(self, account, log_level=logging.WARNING, sandbox=False):
        """Create a new `godaddypy.Client` object

        :type account: godaddypy.Account
        :param account: The godaddypy.Account object to create auth headers with.
        """

        # Logging setup
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        self.logger.addHandler(logging.StreamHandler())

        # Templates
        if sandbox:
            self.API_TEMPLATE = 'https://api.ote-godaddy.com/v1'
        else:
            self.API_TEMPLATE = 'https://api.godaddy.com/v1'

        self.DOMAINS = '/domains'
        self.DOMAIN_INFO = '/domains/{domain}'
        self.RECORDS = '/domains/{domain}/records'
        self.RECORDS_TYPE = '/domains/{domain}/records/{type}'
        self.RECORDS_TYPE_NAME = '/domains/{domain}/records/{type}/{name}'

        self.account = account

    def _build_record_url(self, domain, record_type=None, name=None):
        url = self.API_TEMPLATE

        if name is None and record_type is None:
            url += self.RECORDS.format(domain=domain)
        elif name is None and record_type is not None:
            url += self.RECORDS_TYPE.format(domain=domain, type=record_type)
        elif name is not None and record_type is None:
            raise ValueError("If name is specified, type must also be specified")
        else:
            url += self.RECORDS_TYPE_NAME.format(domain=domain, type=record_type, name=name)

        return url

    def _get_headers(self):
        return self.account.get_auth_headers()

    def _get_json_from_response(self, url, json=None, **kwargs):
        return self._request_submit(requests.get, url=url, json=json, **kwargs).json()

    def _log_response_from_method(self, req_type, resp):
        self.logger.debug('[{req_type}] response: {resp}'.format(resp=resp, req_type=req_type.upper()))
        self.logger.debug('Response data: {}'.format(resp.content))

    def _log_request_from_method(self, req_type, request):
        self.logger.debug('[{req_type}] request: {req}'.format(req=request, req_type=req_type.upper()))

    def _patch(self, url, json=None, **kwargs):
        return self._request_submit(requests.patch, url=url, json=json, **kwargs)

    def _post(self, url, json=None, **kwargs):
        return self._request_submit(requests.post, url=url, json=json, **kwargs)

    def _put(self, url, json=None, **kwargs):
        return self._request_submit(requests.put, url=url, json=json, **kwargs)

    @staticmethod
    def _remove_key_from_dict(dictionary, key_to_remove):
        return {key: value for key, value in dictionary.items() if key != key_to_remove}

    def _request_submit(self, function, **kwargs):
        """A helper function that will wrap any requests we make.

        :param function: a function reference to the requests method to invoke
        :param kwargs: any extra arguments that requests.request takes

        :type function: (url: Any, data: Any, json: Any, kwargs: Dict)
        """
        self._log_request_from_method(function.__name__, kwargs.get('json'))
        resp = function(headers=self._get_headers(), **kwargs)
        self._log_response_from_method(function.__name__, resp)
        self._validate_response_success(resp)
        return resp

    def _scope_control_account(self, account):
        if account is None:
            return self.account
        else:
            return account

    @staticmethod
    def _validate_response_success(response):
        if response.status_code != 200:
            raise BadResponse(response.json())

    def add_record(self, domain, record):
        """Adds the specified DNS record to a domain.

        :param domain: the domain to add the record to
        :param record: the record to add
        """
        self.add_records(domain, [record])

        # If we didn't get any exceptions, return True to let the user know
        return True

    def add_records(self, domain, records):
        """Adds the specified DNS records to a domain.

        :param domain: the domain to add the records to
        :param records: the records to add
        """
        url = self.API_TEMPLATE + self.RECORDS.format(domain=domain)
        self._patch(url, json=records)
        logging.info('Added records @ {}'.format(records))

        # If we didn't get any exceptions, return True to let the user know
        return True

    def get_domain_info(self, domain):
        """Get the GoDaddy supplied information about a specific domain.

        :param domain: The domain to obtain info about.
        :type domain: str

        :return A JSON string representing the domain information
        """
        url = self.API_TEMPLATE + self.DOMAIN_INFO.format(domain=domain)
        return self._get_json_from_response(url)

    def get_domains(self):
        """Returns a list of ACTIVE domains for the authenticated user.
        """
        url = self.API_TEMPLATE + self.DOMAINS
        data = self._get_json_from_response(url)

        domains = list()
        for item in data:
            domain = item['domain']
            if item['status'] == 'ACTIVE':
                domains.append(domain)
                self.logger.info('Discovered domains: {}'.format(domain))

        return domains

    def get_records(self, domain, record_type=None, name=None):
        """Returns records from a single domain.  You can specify type/name as filters for the records returned.  If
        you specify a name you MUST also specify a type.

        :param domain: the domain to get DNS information from
        :param record_type: the type of record(s) to retrieve
        :param name: the name of the record(s) to retrieve
        """

        url = self._build_record_url(domain, record_type=record_type, name=name)
        data = self._get_json_from_response(url)
        self.logger.info('Retrieved {} record(s) from {}.'.format(len(data), domain))

        return data

    def replace_records(self, domain, records, record_type=None, name=None):
        """This will replace all records at the domain.  Record type and record name can be provided to filter
        which records to replace.

        :param domain: the domain to replace records at
        :param records: the records you will be saving
        :param record_type: the type of records you want to replace (eg. only replace 'A' records)
        :param name: the name of records you want to replace (eg. only replace records with name 'test')

        :return: True if no exceptions occurred
        """

        url = self._build_record_url(domain, name=name, record_type=record_type)
        self._put(url, json=records)

        # If we didn't get any exceptions, return True to let the user know
        return True

    def update_ip(self, ip, record_type='A', domains=None, subdomains=None):
        """Update the IP address in all records, specified by type, to the value of ip.  Returns True if no
        exceptions occurred during the update.  If no domains are provided, all domains returned from
        self.get_domains() will be updated.  By default, only A records are updated.

        :param record_type: The type of records to update (eg. 'A')
        :param ip: The new IP address (eg. '123.1.2.255')
        :param domains: A list of the domains you want to update (eg. ['123.com','abc.net'])
        :param subdomains: A list of the subdomains you want to update (eg. ['www','dev'])

        :type record_type: str
        :type ip: str
        :type domains: str, list of str
        :type subdomains: str, list of str

        :return: True if no exceptions occurred
        """

        if domains is None:
            domains = self.get_domains()
        elif sys.version_info < (3, 0):
            if type(domains) == str or type(domains) == unicode:
                domains = [domains]
        elif sys.version_info >= (3, 0) and type(domains) == str:
            domains = [domains]
        elif type(domains) == list:
            pass
        else:
            raise SystemError("Domains must be type 'list' or type 'str'")

        for domain in domains:
            a_records = self.get_records(domain, record_type=record_type)
            for record in a_records:
                r_name = str(record['name'])
                r_ip = str(record['data'])

                if not r_ip == ip:

                    if ((subdomains is None) or
                            (type(subdomains) == list and subdomains.count(r_name)) or
                            (type(subdomains) == str and subdomains == r_name)):
                        record.update(data=str(ip))
                        self.update_record(domain, record)

        # If we didn't get any exceptions, return True to let the user know
        return True

    def delete_records(self, domain, name, record_type=None):
        """Deletes records by name.  You can also add a record type, which will only delete records with the
        specified type/name combo.  If no record type is specified, ALL records that have a matching name will be
        deleted.

        This is haphazard functionality.   I DO NOT recommend using this in Production code, as your entire DNS record
        set could be deleted, depending on the fickleness of GoDaddy.  Unfortunately, they do not expose a proper
        "delete record" call, so there isn't much one can do here...

        :param domain: the domain to delete records from
        :param name: the name of records to remove
        :param record_type: the type of records to remove

        :return: True if no exceptions occurred
        """

        records = self.get_records(domain)
        if records is None:
            return False  # we don't want to replace the records with nothing at all
        save = list()
        deleted = 0
        for record in records:
            if (record_type == str(record['type']) or record_type is None) and name == str(record['name']):
                deleted += 1
            else:
                save.append(record)

        self.replace_records(domain, records=save)
        self.logger.info("Deleted {} records @ {}".format(deleted, domain))

        # If we didn't get any exceptions, return True to let the user know
        return True

    def update_record(self, domain, record, record_type=None, name=None):
        """Call to GoDaddy API to update a single DNS record

        :param name: only required if the record is None (deletion)
        :param record_type: only required if the record is None (deletion)
        :param domain: the domain where the DNS belongs to (eg. 'example.com')
        :param record: dict with record info (ex. {'name': 'dynamic', 'ttl': 3600, 'data': '1.1.1.1', 'type': 'A'})

        :return: True if no exceptions occurred
        """
        if record_type is None:
            record_type = record['type']
        if name is None:
            name = record['name']

        url = self.API_TEMPLATE + self.RECORDS_TYPE_NAME.format(domain=domain, type=record_type, name=name)
        self._put(url, json=record)
        logging.info(
            'Updated record. Domain {} name {} type {}'.format(domain, str(record['name']), str(record['type'])))

        # If we didn't get any exceptions, return True to let the user know
        return True

    def update_record_ip(self, ip, domain, name, record_type):
        """Update the IP address(es) for (a) domain(s) specified by type and name.

        :param ip: the new IP for the DNS record (ex. '123.1.2.255')
        :param domain: the domain where the DNS belongs to (ex. 'example.com')
        :param name: the DNS record name to be updated (ex. 'dynamic')
        :param record_type: Record type (ex. 'CNAME', 'A'...)

        :return: True if no exceptions occurred
        """

        records = self.get_records(domain, name=name, record_type=record_type)
        data = {'data': str(ip)}
        for _rec in records:
            _rec.update(data)
            self.update_record(domain, _rec)

        # If we didn't get any exceptions, return True to let the user know
        return True

    def check_domain_availability(self, domain):
        """
        Check if domain name is available for purchase
        :param domain: Domain name to check
        :return: {u'available': False,
                  u'domain': u'example.com',
                  u'definitive': True,
                  u'price': 7990000,
                  u'period': 1,
                  u'currency': u'USD'}
        """
        url = self.API_TEMPLATE + self.DOMAINS + '/available'
        params = {'domain': domain}
        return self._get_json_from_response(url, params=params)

    def get_top_level_domains(self, names_only=True):
        """
        Full list of TLDs that are available for sale
        :param names_only:
        :return: [{u'type': u'GENERIC', u'name': u'academy'}, ...]
        """
        url = self.API_TEMPLATE + self.DOMAINS + '/tlds'
        response = self._get_json_from_response(url)
        if names_only:
            return [a['name'] for a in response]
        return response

    def get_purchase_schema(self, tld):
        __com_schema = {u'$schema': u'http://json-schema.org/draft-04/schema#',
                        u'additionalProperties': False,
                        u'definitions': {u'Address': {u'additionalProperties': False,
                                                      u'id': u'Address',
                                                      u'properties': {u'address1': {u'format': u'street-address',
                                                                                    u'maxLength': 41,
                                                                                    u'type': u'string'},
                                                                      u'address2': {u'format': u'street-address2',
                                                                                    u'maxLength': 41,
                                                                                    u'type': u'string'},
                                                                      u'city': {u'format': u'city-name',
                                                                                u'maxLength': 30,
                                                                                u'type': u'string'},
                                                                      u'country': {u'defaultValue': u'US',
                                                                                   u'description': u"Two-letter ISO country code to be used as a hint for target region<br/><br/>\nNOTE: These are sample values, there are many\n<a href='http://www.iso.org/iso/country_codes.htm'>more</a>",
                                                                                   u'enum': [u'AC',
                                                                                             u'AD',
                                                                                             u'AE',
                                                                                             u'AF',
                                                                                             u'AG',
                                                                                             u'AI',
                                                                                             u'AL',
                                                                                             u'AM',
                                                                                             u'AO',
                                                                                             u'AQ',
                                                                                             u'AR',
                                                                                             u'AS',
                                                                                             u'AT',
                                                                                             u'AU',
                                                                                             u'AW',
                                                                                             u'AX',
                                                                                             u'AZ',
                                                                                             u'BA',
                                                                                             u'BB',
                                                                                             u'BD',
                                                                                             u'BE',
                                                                                             u'BF',
                                                                                             u'BG',
                                                                                             u'BH',
                                                                                             u'BI',
                                                                                             u'BJ',
                                                                                             u'BM',
                                                                                             u'BN',
                                                                                             u'BO',
                                                                                             u'BQ',
                                                                                             u'BR',
                                                                                             u'BS',
                                                                                             u'BT',
                                                                                             u'BV',
                                                                                             u'BW',
                                                                                             u'BY',
                                                                                             u'BZ',
                                                                                             u'CA',
                                                                                             u'CC',
                                                                                             u'CD',
                                                                                             u'CF',
                                                                                             u'CG',
                                                                                             u'CH',
                                                                                             u'CI',
                                                                                             u'CK',
                                                                                             u'CL',
                                                                                             u'CM',
                                                                                             u'CN',
                                                                                             u'CO',
                                                                                             u'CR',
                                                                                             u'CV',
                                                                                             u'CW',
                                                                                             u'CX',
                                                                                             u'CY',
                                                                                             u'CZ',
                                                                                             u'DE',
                                                                                             u'DJ',
                                                                                             u'DK',
                                                                                             u'DM',
                                                                                             u'DO',
                                                                                             u'DZ',
                                                                                             u'EC',
                                                                                             u'EE',
                                                                                             u'EG',
                                                                                             u'EH',
                                                                                             u'ER',
                                                                                             u'ES',
                                                                                             u'ET',
                                                                                             u'FI',
                                                                                             u'FJ',
                                                                                             u'FK',
                                                                                             u'FM',
                                                                                             u'FO',
                                                                                             u'FR',
                                                                                             u'GA',
                                                                                             u'GB',
                                                                                             u'GD',
                                                                                             u'GE',
                                                                                             u'GF',
                                                                                             u'GG',
                                                                                             u'GH',
                                                                                             u'GI',
                                                                                             u'GL',
                                                                                             u'GM',
                                                                                             u'GN',
                                                                                             u'GP',
                                                                                             u'GQ',
                                                                                             u'GR',
                                                                                             u'GS',
                                                                                             u'GT',
                                                                                             u'GU',
                                                                                             u'GW',
                                                                                             u'GY',
                                                                                             u'HK',
                                                                                             u'HM',
                                                                                             u'HN',
                                                                                             u'HR',
                                                                                             u'HT',
                                                                                             u'HU',
                                                                                             u'ID',
                                                                                             u'IE',
                                                                                             u'IL',
                                                                                             u'IM',
                                                                                             u'IN',
                                                                                             u'IO',
                                                                                             u'IQ',
                                                                                             u'IS',
                                                                                             u'IT',
                                                                                             u'JE',
                                                                                             u'JM',
                                                                                             u'JO',
                                                                                             u'JP',
                                                                                             u'KE',
                                                                                             u'KG',
                                                                                             u'KH',
                                                                                             u'KI',
                                                                                             u'KM',
                                                                                             u'KN',
                                                                                             u'KR',
                                                                                             u'KV',
                                                                                             u'KW',
                                                                                             u'KY',
                                                                                             u'KZ',
                                                                                             u'LA',
                                                                                             u'LB',
                                                                                             u'LC',
                                                                                             u'LI',
                                                                                             u'LK',
                                                                                             u'LR',
                                                                                             u'LS',
                                                                                             u'LT',
                                                                                             u'LU',
                                                                                             u'LV',
                                                                                             u'LY',
                                                                                             u'MA',
                                                                                             u'MC',
                                                                                             u'MD',
                                                                                             u'ME',
                                                                                             u'MG',
                                                                                             u'MH',
                                                                                             u'MK',
                                                                                             u'ML',
                                                                                             u'MM',
                                                                                             u'MN',
                                                                                             u'MO',
                                                                                             u'MP',
                                                                                             u'MQ',
                                                                                             u'MR',
                                                                                             u'MS',
                                                                                             u'MT',
                                                                                             u'MU',
                                                                                             u'MV',
                                                                                             u'MW',
                                                                                             u'MX',
                                                                                             u'MY',
                                                                                             u'MZ',
                                                                                             u'NA',
                                                                                             u'NC',
                                                                                             u'NE',
                                                                                             u'NF',
                                                                                             u'NG',
                                                                                             u'NI',
                                                                                             u'NL',
                                                                                             u'NO',
                                                                                             u'NP',
                                                                                             u'NR',
                                                                                             u'NU',
                                                                                             u'NZ',
                                                                                             u'OM',
                                                                                             u'PA',
                                                                                             u'PE',
                                                                                             u'PF',
                                                                                             u'PG',
                                                                                             u'PH',
                                                                                             u'PK',
                                                                                             u'PL',
                                                                                             u'PM',
                                                                                             u'PN',
                                                                                             u'PR',
                                                                                             u'PS',
                                                                                             u'PT',
                                                                                             u'PW',
                                                                                             u'PY',
                                                                                             u'QA',
                                                                                             u'RE',
                                                                                             u'RO',
                                                                                             u'RS',
                                                                                             u'RU',
                                                                                             u'RW',
                                                                                             u'SA',
                                                                                             u'SB',
                                                                                             u'SC',
                                                                                             u'SE',
                                                                                             u'SG',
                                                                                             u'SH',
                                                                                             u'SI',
                                                                                             u'SJ',
                                                                                             u'SK',
                                                                                             u'SL',
                                                                                             u'SM',
                                                                                             u'SN',
                                                                                             u'SO',
                                                                                             u'SR',
                                                                                             u'ST',
                                                                                             u'SV',
                                                                                             u'SX',
                                                                                             u'SZ',
                                                                                             u'TC',
                                                                                             u'TD',
                                                                                             u'TF',
                                                                                             u'TG',
                                                                                             u'TH',
                                                                                             u'TJ',
                                                                                             u'TK',
                                                                                             u'TL',
                                                                                             u'TM',
                                                                                             u'TN',
                                                                                             u'TO',
                                                                                             u'TP',
                                                                                             u'TR',
                                                                                             u'TT',
                                                                                             u'TV',
                                                                                             u'TW',
                                                                                             u'TZ',
                                                                                             u'UA',
                                                                                             u'UG',
                                                                                             u'UM',
                                                                                             u'US',
                                                                                             u'UY',
                                                                                             u'UZ',
                                                                                             u'VA',
                                                                                             u'VC',
                                                                                             u'VE',
                                                                                             u'VG',
                                                                                             u'VI',
                                                                                             u'VN',
                                                                                             u'VU',
                                                                                             u'WF',
                                                                                             u'WS',
                                                                                             u'YE',
                                                                                             u'YT',
                                                                                             u'ZA',
                                                                                             u'ZM',
                                                                                             u'ZW'],
                                                                                   u'format': u'iso-country-code',
                                                                                   u'type': u'string'},
                                                                      u'postalCode': {u'description': u'Postal or zip code',
                                                                                      u'format': u'postal-code',
                                                                                      u'maxLength': 10,
                                                                                      u'minLength': 2,
                                                                                      u'type': u'string'},
                                                                      u'state': {u'description': u'State or province or territory',
                                                                                 u'format': u'state-province-territory',
                                                                                 u'maxLength': 30,
                                                                                 u'minLength': 2,
                                                                                 u'type': u'string'}},
                                                      u'required': [u'address1',
                                                                    u'city',
                                                                    u'state',
                                                                    u'postalCode',
                                                                    u'country']},
                                         u'Consent': {u'additionalProperties': False,
                                                      u'id': u'Consent',
                                                      u'properties': {u'agreedAt': {u'description': u'Timestamp indicating when the end-user consented to '
                                                                                                    u'these legal agreements',
                                                                                    u'format': u'iso-datetime',
                                                                                    u'type': u'string'},
                                                                      u'agreedBy': {u'description': u"Originating client IP address of the end-user's computer "
                                                                                                    u"when they consented to these legal agreements",
                                                                                    u'type': u'string'},
                                                                      u'agreementKeys': {u'description': u'Unique identifiers of the legal agreements to which '
                                                                                                         u'the end-user has agreed, as returned from '
                                                                                                         u'the/domains/agreements endpoint',
                                                                                         u'items': {u'type': u'string'},
                                                                                         u'type': u'array'}},
                                                      u'required': [u'agreementKeys',
                                                                    u'agreedBy',
                                                                    u'agreedAt']},
                                         u'Contact': {u'additionalProperties': False,
                                                      u'id': u'Contact',
                                                      u'properties': {u'addressMailing': {u'$ref': u'https://domain.api.int.ote-godaddy.com/DomainPurchase#/definitions/Address'},
                                                                      u'email': {u'format': u'email',
                                                                                 u'maxLength': 80,
                                                                                 u'type': u'string'},
                                                                      u'fax': {u'format': u'phone',
                                                                               u'maxLength': 17,
                                                                               u'type': u'string'},
                                                                      u'jobTitle': {u'type': u'string'},
                                                                      u'nameFirst': {u'format': u'person-name',
                                                                                     u'maxLength': 30,
                                                                                     u'type': u'string'},
                                                                      u'nameLast': {u'format': u'person-name',
                                                                                    u'maxLength': 30,
                                                                                    u'type': u'string'},
                                                                      u'nameMiddle': {u'type': u'string'},
                                                                      u'organization': {u'format': u'organization-name',
                                                                                        u'maxLength': 100,
                                                                                        u'type': u'string'},
                                                                      u'phone': {u'format': u'phone',
                                                                                 u'maxLength': 17,
                                                                                 u'type': u'string'}},
                                                      u'required': [u'nameFirst',
                                                                    u'nameLast',
                                                                    u'email',
                                                                    u'phone',
                                                                    u'addressMailing']}},
                        u'id': u'https://domain.api.int.ote-godaddy.com/DomainPurchase#',
                        u'properties': {u'consent': {u'$ref': u'https://domain.api.int.ote-godaddy.com/DomainPurchase#/definitions/Consent'},
                                        u'contactAdmin': {u'$ref': u'https://domain.api.int.ote-godaddy.com/DomainPurchase#/definitions/Contact'},
                                        u'contactBilling': {u'$ref': u'https://domain.api.int.ote-godaddy.com/DomainPurchase#/definitions/Contact'},
                                        u'contactRegistrant': {u'$ref': u'https://domain.api.int.ote-godaddy.com/DomainPurchase#/definitions/Contact'},
                                        u'contactTech': {u'$ref': u'https://domain.api.int.ote-godaddy.com/DomainPurchase#/definitions/Contact'},
                                        u'domain': {u'format': u'domain',
                                                    u'pattern': u'^[^.]{1,63}(\\.[^.]{2,}){1,2}$',
                                                    u'type': u'string'},
                                        u'nameServers': {u'items': {u'format': u'host-name',
                                                                    u'pattern': u'([^.]+\\.)*[^.]+\\.[^.]+',
                                                                    u'type': u'string'},
                                                         u'maxItems': 13,
                                                         u'minItems': 0,
                                                         u'type': u'array'},
                                        u'period': {u'defaultValue': 1,
                                                    u'format': u'integer-positive',
                                                    u'maximum': 10,
                                                    u'minimum': 1,
                                                    u'pattern': u'[1]?[0-9]',
                                                    u'type': u'integer'},
                                        u'privacy': {u'defaultValue': False, u'type': u'boolean'},
                                        u'renewAuto': {u'defaultValue': True, u'type': u'boolean'}},
                        u'required': [u'domain',
                                      u'consent',
                                      u'contactAdmin',
                                      u'contactBilling',
                                      u'contactRegistrant',
                                      u'contactTech']}

        url = self.API_TEMPLATE + self.DOMAINS + '/purchase/schema/' + tld
        return self._get_json_from_response(url)

    def create_purchase_data_for_domain_registation(self, domain_name, first_name, last_name, email, phone, address1, city, state, postalCode, country, host_ip):
        tld = domain_name.split('.')[-1]
        if tld in ('com',):
            agreements = self.get_agreements_for_tld(tld)
            print(agreements)
            address = {
                'address1': address1,
                'city': city,
                'state': state,
                'postalCode': postalCode,
                'country': country
            }
            contact = {
                'nameFirst': first_name,
                'nameLast': last_name,
                'email': email,
                'phone': phone,
                'addressMailing': address
            }
            purchase_data = {
                'domain': domain_name,
                'consent': {
                    'agreementKeys': [agreements[0]],
                    'agreedBy': host_ip,
                    'agreedAt': datetime.now().isoformat() + 'Z'
                },
                'contactAdmin': contact,
                'contactBilling': contact,
                'contactRegistrant': contact,
                'contactTech': contact
            }
            self.validate_purchase_data_for_domain_registation(purchase_data)
            return purchase_data

    def validate_purchase_data_for_domain_registation(self, purchase_data):
        url = self.API_TEMPLATE + self.DOMAINS + '/purchase/validate'
        params = purchase_data
        return self._post(url, params)

    def get_agreements_for_tld(self, tld, privacy_required=False, keys_only=True):
        url = self.API_TEMPLATE + self.DOMAINS + '/agreements'
        params = {'tlds': tld, 'privacy': privacy_required}
        response = self._get_json_from_response(url, params=params)
        if keys_only:
            return [a['agreementKey'].encode('utf8') for a in response]
        return response


class BadResponse(Exception):
    def __init__(self, message, *args, **kwargs):
        self._message = message
        super(BadResponse, *args, **kwargs)

    def __str__(self, *args, **kwargs):
        return 'Response Data: {}'.format(self._message)
