 #! /usr/bin/env python3
 
"""
Ionut Pirva
January 2022

AVI Custom DNS Script
Create, Update, Delete DNS Records on AWS Route53
Implement DNS_RECORD_A V4 for VS IP

Access Key ID and Secret Access Key needed for auth

Base: https://avinetworks.com/docs/21.1/custom-dns-profile/

# dynamic entries for VS
dns_info
    0
        fqdn: xxx.test.cloud
        ttl: 123
        type: DNS_RECORD_A
        algorithm: DNS_RECORD_RESPONSE_CONSISTENT_HASH
        metadata: {'fqdn':'xxx.test.cloud', 'ttl':60, 'type':'DNS_RECORD_A', 'ip_qddress': '192.168.0.5', 'f_ip_address':'33.72.93.135', 'metadata':''}

metadata content is what AVI sends to the script
# in case we look to the record_info
metadata: {'fqdn':'xxx.test.cloud', 'ttl':60, 'type':'DNS_RECORD_A', 'ip_qddress': '192.168.0.5', 'f_ip_address':'33.72.93.135', 'metadata':''}
# in case we look to params
metadata: {'ACCESS_KEY_ID':'', 'SECRET_ACCESS_KEY':'', 'HOSTED_ZONE_ID':''}

type: DNS_RECORD_A, DNS_RECORD_TXT, DNS_RECORD_NS, DNS_RECORD_CNAME
"""
import time
import boto3
import botocore

def CreateOrUpdateRecord(record_info, params):

    # metadata: {'fqdn':'xxx.test.cloud', 'ttl':60, 'type':'DNS_RECORD_A', 'ip_address': '192.168.0.5', 'f_ip_address':'33.72.93.135', 'metadata':''}
    # scripts parameters  ACCESS_KEY_ID (required), SECRET_ACCESS_KEY (required), HOSTED_ZONE_ID (required), DNS_TTL, PUBLIC_OR_PRIVATE

    # supported DNS records types
    dns_records = {"DNS_RECORD_A": "A"}
    dns_action = "create/update"

    # check that the scripts parameters are set
    try:
        aws_access_key_id = params.get("ACCESS_KEY_ID")
        aws_secret_access_key = params.get("SECRET_ACCESS_KEY")
        aws_hosted_zone_id = params.get("HOSTED_ZONE_ID")
    except Exception as e:
        return f"Missing prameters: {str(e)}"

    # read received info
    fqdn = record_info.get("fqdn", None)
    ip_address = record_info.get("ip_address", None)
    f_ip_address = record_info.get("f_ip_address", None)
    metadata = record_info.get("metadata", None)
    type = record_info.get("type", None)
    
    if type not in dns_records.keys():
        return f"The DNS records supported are {str(dns_records.keys())}"

    if params.get("DNS_TTL"):
        dns_ttl = params.get("DNS_TTL")
    else:
        dns_ttl = record_info.get("ttl", 3600)
    
    dns_ttl = int(dns_ttl)

    dns_record_ip = params.get("PUBLIC_OR_PRIVATE", "PUBLIC")

    if dns_record_ip.lower() == "public":
        dns_ip_address = f_ip_address
    if dns_record_ip.lower() == "private":
        dns_ip_address = ip_address
    
    if dns_ip_address is None:
        return f"The IP Address for the DNS A Record must be defined. Check that the PUBLIC_OR_PRIVATE is set based on your environment."

    client = boto3.client(
        "route53",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    error_msg = None
    error_code = None
    response = None

    # try to create, if error code "InvalidChangeBatch", try to update
    # payload
    aws_route53_change={
            'Changes': [
                {
                    'ResourceRecordSet': {
                        'Name': fqdn,
                        'ResourceRecords': [
                            {
                                'Value': dns_ip_address,
                            },
                        ],
                        'TTL': dns_ttl,
                        'Type': 'A',
                    },
                },
            ],
            'Comment': '',
    }

    if dns_records[type] == "A":
        try:
            aws_route53_change["Changes"][0]["Action"] = "CREATE"
            response = client.change_resource_record_sets(
                ChangeBatch=aws_route53_change,
                HostedZoneId=aws_hosted_zone_id,
            )
        except botocore.exceptions.ClientError as error:
            error = error.response['Error']
            error_code = error['Code']            
            if error_code == "InvalidChangeBatch":
                pass
                try:
                    aws_route53_change["Changes"][0]["Action"] = "UPSERT"
                    response = client.change_resource_record_sets(
                        ChangeBatch=aws_route53_change,
                        HostedZoneId=aws_hosted_zone_id,
                    )
                except botocore.exceptions.ClientError as error:
                    error = error.response['Error']
                    error_msg = error

    # response
    # {'ResponseMetadata': {'RequestId': '69133010-7c84-48ed-8d48-bdb07831fe7f', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '69133010-7c84-48ed-8d48-bdb07831fe7f', 'content-type': 'text/xml', 
    # 'content-length': '301', 'date': 'Sat, 08 Jan 2022 19:26:06 GMT'}, 'RetryAttempts': 0}, 'ChangeInfo': {'Id': '/change/XYZ', 'Status': 'PENDING', 
    # 'SubmittedAt': datetime.datetime(2022, 1, 8, 19, 26, 7, 726000, tzinfo=tzutc()), 'Comment': ''}}

    if error_msg is not None:
        raise Exception(f"DNS record {dns_action} failed with {str(error_msg)}")

    change_info = response.get("ChangeInfo", None)
    change_id = change_info.get("Id", None)
    change_status = change_info.get("Status", None)

    # get status of the change
    # wait for the change to get insync
    if change_status.lower() == "pending":

        new_change_status = ""
        loop_max = 30 # seconds
        loop_exit = 0
        loop_sleep = 2

        while True:
            print(f"[{loop_exit} seconds] Waiting for the DNS record {dns_action} to get sync'ed ...")
            if loop_exit > loop_max:
                print("Timeout expired")
            if loop_exit > loop_max or new_change_status.lower() == "insync":
                print(f"DNS record {dns_action} status is {new_change_status}")
                response = response_change
                break

            if new_change_status.lower() != "insync":
                response_change = client.get_change(
                    Id=change_id
                )
                time.sleep(loop_sleep)
                new_change_status = response_change["ChangeInfo"]["Status"]
                loop_exit += loop_sleep
        
    return response

 
def DeleteRecord(record_info, params):

    # supported DNS records types
    dns_records = {"DNS_RECORD_A": "A"}
    dns_action = "delete"

    # check that the scripts parameters are set
    try:
        aws_access_key_id = params.get("ACCESS_KEY_ID")
        aws_secret_access_key = params.get("SECRET_ACCESS_KEY")
        aws_hosted_zone_id = params.get("HOSTED_ZONE_ID")
    except Exception as e:
        return f"Missing prameters: {str(e)}"

    # read received info
    fqdn = record_info.get("fqdn", None)
    ip_address = record_info.get("ip_address", None)
    f_ip_address = record_info.get("f_ip_address", None)
    metadata = record_info.get("metadata", None)
    type = record_info.get("type", None)
    
    if type not in dns_records.keys():
        return f"The DNS records supported are {str(dns_records.keys())}"
    
    dns_ttl = params.get("DNS_TTL", 3600)
    
    dns_ttl = int(dns_ttl)

    dns_record_ip = params.get("PUBLIC_OR_PRIVATE", "PUBLIC")

    if dns_record_ip.lower() == "public":
        dns_ip_address = f_ip_address
    if dns_record_ip.lower() == "private":
        dns_ip_address = ip_address
    
    if dns_ip_address is None:
        return f"The IP Address for the DNS A Record must be defined. Check that the PUBLIC_OR_PRIVATE is set based on your environment."

    client = boto3.client(
        "route53",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )
    
    error_msg = None
    error_code = None
    response = None

    # try to create, if error code "InvalidChangeBatch", try to update
    # payload
    aws_route53_change={
        'Changes': [
            {
                'ResourceRecordSet': {
                    'Name': fqdn,
                    'ResourceRecords': [
                        {
                            'Value': dns_ip_address,
                        },
                    ],
                    'TTL': dns_ttl,
                    'Type': 'A',
                },
            },
        ],
        'Comment': '',
    }

    if dns_records[type] == "A":
        try:
            aws_route53_change["Changes"][0]["Action"] = "DELETE"
            response = client.change_resource_record_sets(
                ChangeBatch=aws_route53_change,
                HostedZoneId=aws_hosted_zone_id,
            )
        except botocore.exceptions.ClientError as error:
            error = error.response['Error']
            error_code = error['Code']          
            error_msg = error

    if error_msg is not None:
        raise Exception(f"DNS record {dns_action} failed with {str(error_msg)}")

    # response
    # {'ResponseMetadata': {'RequestId': '4eadce00-8c8c-4073-8cab-cce5d4a8215f', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '4eadce00-8c8c-4073-8cab-cce5d4a8215f', 
    # 'content-type': 'text/xml', 'content-length': '301', 'date': 'Sat, 08 Jan 2022 22:23:19 GMT'}, 'RetryAttempts': 0}, 'ChangeInfo': {'Id': '/change/XYZ', 
    # 'Status': 'PENDING', 'SubmittedAt': datetime.datetime(2022, 1, 8, 22, 23, 20, 492000, tzinfo=tzutc()), 'Comment': ''}}

    change_info = response.get("ChangeInfo", None)
    change_id = change_info.get("Id", None)
    change_status = change_info.get("Status", None)

    # get status of the change
    # wait for the change to get insync
    if change_status.lower() == "pending":

        new_change_status = ""
        loop_max = 30 # seconds
        loop_exit = 0
        loop_sleep = 2

        while True:
            if loop_exit > loop_max:
                print("Timeout expired")
            print(f"[{loop_exit} seconds] Waiting for the DNS record {dns_action} to get sync'ed ...")
            if loop_exit > loop_max or new_change_status.lower() == "insync":
                print(f"DNS record {dns_action} status is {new_change_status}")
                response = response_change
                break

            if new_change_status.lower() != "insync":
                response_change = client.get_change(
                    Id=change_id
                )
                time.sleep(loop_sleep)
                new_change_status = response_change["ChangeInfo"]["Status"]
                loop_exit += loop_sleep
        
    return response