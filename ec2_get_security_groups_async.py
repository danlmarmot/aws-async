import asyncio
from aiohttp import ClientSession

import requests

import datetime
import hashlib
import hmac
import urllib.parse

import os
import sys

# from botocore.auth import SigV4Auth
# from botocore.awsrequest import AWSRequest
# from botocore.session import Session

ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY_ID')
SECRET_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
if ACCESS_KEY is None or SECRET_KEY is None:
    print('No access key is available.')
    sys.exit()

EC2_ENDPOINT = "https://ec2.amazonaws.com/"


# Some reference docs
# https://charemza.name/blog/posts/aws/python/you-might-not-need-boto-3/
#   Example using S3, does not use boto3 or botocore
# https://www.mathewmarcus.com/blog/asynchronous-aws-api-requests-with-asyncio.html
#   Uses botocore for signing and the like
# https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
#   AWS example in Python on how to create a signed request
#
# In general, AWS recommends using POST rather than GET.


def main():
    region_response = ec2_get_regions_async()
    print(sorted([x['RegionName'] for x in region_response['Regions']]))
    # func_name = 'hello-world-{}'
    # funcs_and_payloads = ((func_name.format(i), dict(hello=i)) for i in range(100))
    #
    # lambda_responses = invoke_all(funcs_and_payloads)
    #
    # Do some further processing with the responses

    # for region_name in regions:
    #     client = boto3_session.client('ec2', region_name=region_name)
    #     ec2_response = client.describe_security_groups()


# def get_regions(boto3_session):
#     ec2c = boto3_session.client('ec2', region_name='us-east-1')  
#
#     try:
#         region_response = ec2c.describe_regions()  
#
#     except botocore.exceptions.ClientError as e: 
#         rv = "Error" + e.response['Error']['Message'] + "(code: " + e.response['Error']['Message'] + ")" 
#         return rv  
#
#     if region_response['ResponseMetadata']['HTTPStatusCode'] != 200:  
#         return "couldn't get regions"  
#
#     regions = sorted([x['RegionName'] for x in region_response['Regions']]))
#
#     return ', '.join(regions)


def ec2_get_regions_sync():
    # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html
    # https://ec2.amazonaws.com/?Action=DescribeRegions
    query = {
        'Action': 'DescribeRegions',
        'Version': '2013-10-15'
    }
    # ensure sort order is correct
    query = {k: query[k] for k in sorted(query)}

    query_str = '&'.join([f'{key}={value}' for key, value in query.items()])

    headers = aws_sig_v4_headers(ACCESS_KEY, SECRET_KEY, {},
                                 'ec2', 'us-east-1',
                                 host='ec2.amazonaws.com',
                                 method="POST",
                                 path='/',
                                 query=query,
                                 payload='')

    request_url = EC2_ENDPOINT + '?' + query_str
    r = requests.post(request_url, headers=headers)
    print('Response code: %d\n' % r.status_code)
    print(r.text)


# def ec2_get_regions_async():
#     async def wrapped():
#         async with ClientSession(raise_for_status=True) as session:
#             regions = ec2_get_regions_aiohttp(session)
#             return await asyncio.gather(regions)
#
#     async def ec2_get_regions_aiohttp(session):
#         query = {
#             'Action': 'DescribeRegions',
#             'Version': '2013-10-15'
#         }
#         # ensure sort order is correct
#         query = {k: query[k] for k in sorted(query)}
#
#         query_str = '&'.join([f'{key}={value}' for key, value in query.items()])
#
#         headers = aws_sig_v4_headers(ACCESS_KEY, SECRET_KEY, {},
#                                      'ec2', 'us-east-1',
#                                      host='ec2.amazonaws.com',
#                                      method="POST",
#                                      path='/',
#                                      query=query,
#                                      payload='')
#
#         request_url = EC2_ENDPOINT + '?' + query_str
#         async with session.post(request_url, headers=headers) as response:
#             return await response
#
#     return asyncio.get_event_loop().run_until_complete(wrapped())


def aws_sig_v4_headers(access_key_id, secret_access_key, pre_auth_headers,
                       service, region, host, method, path, query, payload):
    # from https://charemza.name/blog/posts/aws/python/you-might-not-need-boto-3/
    algorithm = 'AWS4-HMAC-SHA256'

    now = datetime.datetime.utcnow()
    amzdate = now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = now.strftime('%Y%m%d')
    payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    credential_scope = f'{datestamp}/{region}/{service}/aws4_request'

    pre_auth_headers_lower = {
        header_key.lower(): ' '.join(header_value.split())
        for header_key, header_value in pre_auth_headers.items()
    }
    required_headers = {
        'host': host,
        'x-amz-content-sha256': payload_hash,
        'x-amz-date': amzdate,
    }
    headers = {**pre_auth_headers_lower, **required_headers}
    header_keys = sorted(headers.keys())
    signed_headers = ';'.join(header_keys)

    def signature():
        def canonical_request():
            canonical_uri = urllib.parse.quote(path, safe='/~')
            quoted_query = sorted(
                (urllib.parse.quote(key, safe='~'), urllib.parse.quote(value, safe='~'))
                for key, value in query.items()
            )
            canonical_querystring = '&'.join(f'{key}={value}' for key, value in quoted_query)
            canonical_headers = ''.join(f'{key}:{headers[key]}\n' for key in header_keys)

            return f'{method}\n{canonical_uri}\n{canonical_querystring}\n' + \
                   f'{canonical_headers}\n{signed_headers}\n{payload_hash}'

        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        string_to_sign = f'{algorithm}\n{amzdate}\n{credential_scope}\n' + \
                         hashlib.sha256(canonical_request().encode('utf-8')).hexdigest()

        date_key = sign(('AWS4' + secret_access_key).encode('utf-8'), datestamp)
        region_key = sign(date_key, region)
        service_key = sign(region_key, service)
        request_key = sign(service_key, 'aws4_request')
        return sign(request_key, string_to_sign).hex()

    return {
        **pre_auth_headers,
        'x-amz-date': amzdate,
        'x-amz-content-sha256': payload_hash,
        'Authorization': f'{algorithm} Credential={access_key_id}/{credential_scope}, '
                         f'SignedHeaders={signed_headers}, Signature=' + signature(),
    }


if __name__ == '__main__':
    main()
