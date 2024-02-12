# -*- coding: utf-8 -*-

import logging
import re

import nagiosplugin as np
from datetime import datetime

from check_pa.xml_reader import XMLReader, Finder

_log = logging.getLogger('nagiosplugin')


def get_now():
    """
    Extract method for mocking datetime.now.

    :return: datetime.today() object
    """
    return datetime.today()  # pragma: no cover


def create_check(args):
    """
    Creates and configures a check for the certificate command.

    :return: the throughput check.
    """
    return np.Check(
        Certificate(args.host, args.token, args.exclude),
        CertificateContext('certificates', args.range),
        CertificateSummary(args.range))


class Certificate(np.Resource):
    """
    Will fetch the certificates from the REST API and returns a warning if
    the remaining days of the certificate is between the value of warning
    (e. g. 20) and critical (e. g. 0).

    If a certificate has been revoked or excluded, no warning will appear.
    """

    def __init__(self, host, token, exclude):
        self.host = host
        self.token = token
        #self.cmd = '<show><config><running>' \
        #           '<xpath>shared/certificate</xpath>' \
        #           '</running></config></show>'

        self.cmd = '<show><sslmgr-store><config-certificate-info></config-certificate-info></sslmgr-store></show>'

        self.xml_obj = XMLReader(self.host, self.token, self.cmd)
        self.exclude = str(exclude).split(",")

    def probe(self):
        """
        Querys the REST-API and create certificate metrics.

        :return: a certificate metric.
        """
        _log.info('Reading XML from: %s', self.xml_obj.build_request_url())
        soup = self.xml_obj.read()
        _log.debug(soup)

        pattern_date = '(?<=db-exp-date:.\d{12}Z\().+.{3}\w'
        pattern_name = '(?<=db-name: ).+'

        certificates_soup = soup.find('result').get_text()
        certificate_dates = re.finditer(pattern_date,certificates_soup)
        certificate_names = re.findall(pattern_name,certificates_soup)
    
    
        idx=0
        for cert_date in certificate_dates:
            not_valid_after = cert_date.group(0).replace("GMT","").strip()
            _log.info(not_valid_after)
            date_object = datetime.strptime(not_valid_after, '%b %d %H:%M:%S %Y')
            difference = date_object - get_now()
            _log.debug('Certificate %s difference: %s days' % (certificate_names[idx], difference.days))
            yield np.Metric(certificate_names[idx], difference.days,context='certificates')
            idx+=1

        #    try:
        #        status = Finder.find_item(certificate, 'status')
        #    except np.CheckError:
        #        status = ""
        #    if certificate.get('name') not in self.exclude:
        #        if status != "revoked":
        #            yield np.Metric(certificate.get('name'), difference.days,
        #                            context='certificates')

        #for certificate in certificates:
        #    not_valid_after = Finder.find_item(certificate,
        #                                     'db-exp-date').replace(
        #        "GMT", "").strip()<
        #    date_object = datetime.strptime(not_valid_after, '%b %d %H:%M:%S %Y')
        #    difference = date_object - get_now()
        #    _log.debug('Certificate %s difference: %s days' % (
        #        certificate.get('name'), difference.days))
        #    try:
        #        status = Finder.find_item(certificate, 'status')
        #    except np.CheckError:
        #        status = ""
        #    if certificate.get('name') not in self.exclude:
        #        if status != "revoked":
        #            yield np.Metric(certificate.get('name'), difference.days,
        #                            context='certificates')


class CertificateContext(np.Context):
    def __init__(self, name, r,
                 fmt_metric='{name} expires in {valueunit}',
                 result_cls=np.Result):
        super(CertificateContext, self).__init__(name, fmt_metric, result_cls)
        self.r = np.Range(r)

    def evaluate(self, metric, resource):
        """Output depending on given start and end range.

        Returns a warning, if a certificate is between given start and end
        range.
        Returns ok, if a certificate is out of range.

        :param metric:
        :param resource:
        :return:
        """
        if self.r.match(metric.value):
            return self.result_cls(np.Warn, None, metric)
        else:
            return self.result_cls(np.Ok, None, metric)


class CertificateSummary(np.Summary):
    def __init__(self, r):
        self.r = np.Range(r)

    def ok(self, results):
        l = []
        for result in results:
            l.append(result.metric.value)
        output = 'The next certificate will expire in %s days.' % min(l)
        return str(output)

    def problem(self, results):
        l = []
        for result in results:
            if self.r.match(result.metric.value):
                l.append(str(result) + ' days')
        output = ", ".join(l)
        return str(output)
