import requests

import asyncio
import aiohttp

import datetime
import hashlib
import hmac
import urllib.parse
import xml.etree.ElementTree as ET

import os
import sys

ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
if ACCESS_KEY is None or SECRET_KEY is None:
    print("No access key is available.")
    sys.exit()

EC2_ENDPOINT = "https://ec2.amazonaws.com/"

# Some reference docs
# https://charemza.name/blog/posts/aws/python/you-might-not-need-boto-3/
#   Example using S3, does not use boto3 or botocore
# https://www.mathewmarcus.com/blog/asynchronous-aws-api-requests-with-asyncio.html
#   Uses botocore for signing and the like
# https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
#   AWS example in Python on how to create a signed request
#   In general, AWS recommends using POST rather than GET.

# Global session for aiohttp, maintains connection pool, ete etc
_session = None


def main():
    region_names = ec2_get_region_names_async()
    print(region_names)


def ec2_get_region_names_sync():
    # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html
    # https://ec2.amazonaws.com/?Action=DescribeRegions

    query = {"Action": "DescribeRegions", "Version": "2013-10-15"}
    # ensure sort order is correct
    query = {k: query[k] for k in sorted(query)}

    query_str = "&".join([f"{key}={value}" for key, value in query.items()])

    headers = aws_sig_v4_headers(
        ACCESS_KEY,
        SECRET_KEY,
        {},
        "ec2",
        "us-east-1",
        host="ec2.amazonaws.com",
        method="POST",
        path="/",
        query=query,
        payload="",
    )

    request_url = EC2_ENDPOINT + "?" + query_str
    response = requests.post(request_url, headers=headers)

    # parse the XML for region names; note the XML namespace
    region_xml = ET.fromstring(response.text)
    region_names = [
        item.text
        for item in region_xml.iter(
            "{http://ec2.amazonaws.com/doc/2013-10-15/}regionName"
        )
    ]

    return sorted(region_names)


def ec2_get_region_names_async():
    result = asyncio.run(ec2_get_region_names_aiohttp())

    return result


async def ec2_get_region_names_aiohttp():
    query = {"Action": "DescribeRegions", "Version": "2013-10-15"}
    # ensure sort order is correct
    query = {k: query[k] for k in sorted(query)}

    query_str = "&".join([f"{key}={value}" for key, value in query.items()])

    headers = aws_sig_v4_headers(
        ACCESS_KEY,
        SECRET_KEY,
        {},
        "ec2",
        "us-east-1",
        host="ec2.amazonaws.com",
        method="POST",
        path="/",
        query=query,
        payload="",
    )

    request_url = EC2_ENDPOINT + "?" + query_str

    # async with ClientSession() as session:
    session = await get_session()
    response = await session.post(request_url, headers=headers)
    response_text = await response.text()

    # parse the XML for region names; note the XML namespace
    region_xml = ET.fromstring(response_text)
    region_names = sorted(
        [
            item.text
            for item in region_xml.iter(
                "{http://ec2.amazonaws.com/doc/2013-10-15/}regionName"
            )
        ]
    )

    return region_names


def aws_sig_v4_headers(
    access_key_id,
    secret_access_key,
    pre_auth_headers,
    service,
    region,
    host,
    method,
    path,
    query,
    payload,
):
    # from https://charemza.name/blog/posts/aws/python/you-might-not-need-boto-3/
    algorithm = "AWS4-HMAC-SHA256"

    now = datetime.datetime.utcnow()
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"

    pre_auth_headers_lower = {
        header_key.lower(): " ".join(header_value.split())
        for header_key, header_value in pre_auth_headers.items()
    }
    required_headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amzdate,
    }
    headers = {**pre_auth_headers_lower, **required_headers}
    header_keys = sorted(headers.keys())
    signed_headers = ";".join(header_keys)

    def signature():
        def canonical_request():
            canonical_uri = urllib.parse.quote(path, safe="/~")
            quoted_query = sorted(
                (urllib.parse.quote(key, safe="~"), urllib.parse.quote(value, safe="~"))
                for key, value in query.items()
            )
            canonical_querystring = "&".join(
                f"{key}={value}" for key, value in quoted_query
            )
            canonical_headers = "".join(
                f"{key}:{headers[key]}\n" for key in header_keys
            )

            return (
                f"{method}\n{canonical_uri}\n{canonical_querystring}\n"
                + f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
            )

        def sign(key, msg):
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        string_to_sign = (
            f"{algorithm}\n{amzdate}\n{credential_scope}\n"
            + hashlib.sha256(canonical_request().encode("utf-8")).hexdigest()
        )

        date_key = sign(("AWS4" + secret_access_key).encode("utf-8"), datestamp)
        region_key = sign(date_key, region)
        service_key = sign(region_key, service)
        request_key = sign(service_key, "aws4_request")
        return sign(request_key, string_to_sign).hex()

    return {
        **pre_auth_headers,
        "x-amz-date": amzdate,
        "x-amz-content-sha256": payload_hash,
        "Authorization": f"{algorithm} Credential={access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature=" + signature(),
    }


async def get_session():
    global _session
    if _session is None:
        _session = aiohttp.ClientSession()
    return _session


if __name__ == "__main__":
    main()
