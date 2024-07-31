# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import aws_cdk as cdk
import boto3
from aws_cdk import (
    aws_ec2,
    aws_events,
    aws_events_targets,
    aws_iam,
    aws_kms,
    aws_lambda,
    aws_lambda_event_sources,
    aws_s3,
    aws_s3_notifications,
    aws_sns,
    aws_sqs,
)
from aws_cdk import custom_resources as cr
from aws_cdk import region_info
from constructs import Construct

from .aos_deployment import AosDeployment
from .cw_dashboard_siem import CloudWatchDashboardSiem
from .enrichment import Enrichment
from .helper_lambda_functions import HelperLambdaFunctions
from .resource_validator import ResourceValidator

print(__version__)

SOLUTION_NAME = f'SIEM on Amazon OpenSearch Service v{__version__}'
INDEX_METRICS_PERIOD_HOUR = 1

iam_client = boto3.client('iam')
ec2_resource = boto3.resource('ec2')
ec2_client = boto3.client('ec2')
lambda_client = boto3.client('lambda')


def validate_cdk_json(context):
    print('\ncdk.json validation for vpc configuration is starting...\n')
    vpc_type = context.node.try_get_context("vpc_type")
    if vpc_type == 'new':
        print('vpc_type:\t\t\tnew')
        return True
    elif vpc_type == 'import':
        print('vpc_type:\t\t\timport')
    else:
        raise Exception('vpc_type is invalid. You can use "new" or "import". '
                        'Exit. Fix and Try again')

    aos_vpc_id = context.node.try_get_context("imported_vpc_id")
    vpc_client = ec2_resource.Vpc(aos_vpc_id)
    print('checking vpc...')
    vpc_client.state
    print(f'checking vpc id...:\t\t{aos_vpc_id}')
    is_dns_support = vpc_client.describe_attribute(
        Attribute='enableDnsSupport')['EnableDnsSupport']['Value']
    print(f'checking dns support...:\t{is_dns_support}')
    is_dns_hotname = vpc_client.describe_attribute(
        Attribute='enableDnsHostnames')['EnableDnsHostnames']['Value']
    print(f'checking dns hostname...:\t{is_dns_hotname}')
    if not is_dns_support or not is_dns_hotname:
        raise Exception('enable DNS Hostname and DNS Support. Exit...')
    print('checking vpc is...\t\t[PASS]\n')

    subnet_ids_from_the_vpc = []
    subnet_objs_from_the_vpc = vpc_client.subnets.all()
    for subnet_obj in subnet_objs_from_the_vpc:
        subnet_ids_from_the_vpc.append(subnet_obj.id)

    def get_pub_or_priv_subnet(routes_attrs):
        for route in routes_attrs:
            gateway = route.get('GatewayId')
            if gateway and gateway.startswith('igw-'):
                return 'public'
        return 'private'

    validation_result = True
    subnet_types = {}
    routetables = vpc_client.route_tables.all()
    for routetable in routetables:
        rt_client = ec2_resource.RouteTable(routetable.id)
        subnet_type = get_pub_or_priv_subnet(rt_client.routes_attribute)
        for attribute in rt_client.associations_attribute:
            subnetid = attribute.get('SubnetId', "")
            main = attribute.get('Main', "")
            if subnetid:
                subnet_types[subnetid] = subnet_type
            elif main:
                subnet_types['main'] = subnet_type

    print('checking subnet...')
    subnet_ids = get_subnet_ids(context)

    for subnet_id in subnet_ids:
        if subnet_id in subnet_ids_from_the_vpc:
            if subnet_id in subnet_types:
                subnet_type = subnet_types[subnet_id]
            else:
                subnet_type = subnet_types['main']
            if subnet_type == 'private':
                print(f'{subnet_id} is\tprivate')
            elif subnet_type == 'public':
                print(f'{subnet_id} is\tpublic')
                validation_result = False
        else:
            print(f'{subnet_id} is\tnot exist')
            validation_result = False
    if not validation_result:
        raise Exception('subnet is invalid. Modify it.')
    print('checking subnet is...\t\t[PASS]\n')

    # delete unnecessary Security Group
    response = ec2_client.describe_security_groups(
        Filters=[
            {'Name': 'vpc-id', 'Values': [aos_vpc_id]},
            {'Name': 'group-name', 'Values': ['aes-siem-vpc-sg']}],
    )
    if len(response['SecurityGroups']) == 0:
        aos_sg_is_associated = False
        print("security group 'aes-siem-vpc-sg' does not exist")
    else:
        try:
            temp_sg_id = response['SecurityGroups'][0]['GroupId']
            ec2_client.delete_security_group(GroupId=temp_sg_id)
            aos_sg_is_associated = False
            print("security group 'aes-siem-vpc-sg' has been deleted")
        except Exception:
            aos_sg_is_associated = True
            print("security group 'aes-siem-vpc-sg' is used")
    validation_results = {'aos_sg_is_associated': aos_sg_is_associated}

    return validation_results


def get_subnet_ids(context):
    subnet_ids = []
    subnet_ids = context.node.try_get_context('imported_vpc_subnets')
    if not subnet_ids:
        # compatibility for v2.0.0
        sbunet1 = context.node.try_get_context('imported_vpc_subnet1')
        sbunet2 = context.node.try_get_context('imported_vpc_subnet2')
        sbunet3 = context.node.try_get_context('imported_vpc_subnet3')
        subnet_ids = [sbunet1['subnet_id'], sbunet2['subnet_id'],
                      sbunet3['subnet_id']]
    return subnet_ids


def get_subnets(context):
    subnets = []
    subnet_ids = get_subnet_ids(context)
    attributes = ec2_client.describe_subnets(SubnetIds=subnet_ids)
    for attribute in attributes['Subnets']:
        subnet_id = attribute['SubnetId']
        # get associated route id
        response = ec2_client.describe_route_tables(
            Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])
        if len(response['RouteTables']) == 0:
            # get main route id
            vpc_id = context.node.try_get_context("imported_vpc_id")
            response = ec2_client.describe_route_tables(
                Filters=[
                    {'Name': 'association.main', 'Values': ['true']},
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                ])
        route_table_id = (
            response['RouteTables'][0]['Associations'][0]['RouteTableId'])

        subnet = aws_ec2.Subnet.from_subnet_attributes(
            context,
            id=subnet_id,
            subnet_id=subnet_id,
            availability_zone=attribute['AvailabilityZone'],
            ipv4_cidr_block=attribute['CidrBlock'],
            route_table_id=route_table_id)

        subnets.append(subnet)

    return subnets


def check_iam_role(pathprefix):
    role_iterator = iam_client.list_roles(PathPrefix=pathprefix, MaxItems=2)
    if len(role_iterator['Roles']) == 1:
        return True
    else:
        return False


def same_lambda_func_version(func_name):
    try:
        response = lambda_client.list_versions_by_function(
            FunctionName=func_name)
        exist_vers = response['Versions'][0]['Description'].split()
        new_ver = f'v{__version__}'
        if new_ver in exist_vers:
            return True
        else:
            return False
    except Exception:
        return False


class MyAesSiemStack(cdk.Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # check vpc configuration in cdk.json
        if self.node.try_get_context('vpc_type'):
            validation_response = validate_cdk_json(self)
        try:
            aos_sg_is_associated = validation_response.get(
                'aos_sg_is_associated')
        except Exception:
            aos_sg_is_associated = False

        ES_LOADER_TIMEOUT = 600
        PARTITION = region_info.Fact.find(
            self.region, region_info.FactName.PARTITION)
        if not PARTITION:
            PARTITION = 'aws'
        ######################################################################
        # Mapping (REGION / ELB / Lambda Arch)
        ######################################################################
        elb_id_temp = region_info.FactName.ELBV2_ACCOUNT
        elb_map_temp = region_info.RegionInfo.region_map(elb_id_temp)
        no_alb_log_account_list = [
            'ap-south-2', 'ap-southeast-4', 'ca-west-1',
            'eu-central-2', 'eu-south-2',
            'il-central-1', 'me-central-1']
        for acct in no_alb_log_account_list:
            elb_map_temp[acct] = '999999999999'
        region_dict = {}
        # https://aws-data-wrangler.readthedocs.io/en/stable/layers.html
        for region in elb_map_temp:
            # ELB account ID
            region_dict[region] = {'ElbV2AccountId': elb_map_temp[region]}
            arm = aws_lambda.Architecture.ARM_64.name
            x86 = aws_lambda.Architecture.X86_64.name
            # Lambda Arch
            if region in ('af-south-1', 'ap-east-1',
                          'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
                          'ap-south-1', 'ap-south-2',
                          'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3',
                          'ap-southeast-4',
                          'ca-central-1', 'ca-west-1',
                          'eu-central-1', 'eu-north-1', 'eu-central-2',
                          'eu-south-1', 'eu-south-2',
                          'eu-west-1', 'eu-west-2', 'eu-west-3',
                          'il-central-1',
                          'me-central-1', 'me-south-1', 'sa-east-1',
                          'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'):
                region_dict[region]['LambdaArch'] = arm
            else:
                region_dict[region]['LambdaArch'] = x86
        region_mapping = cdk.CfnMapping(
            scope=self, id='RegionMap', mapping=region_dict)

        ######################################################################
        # CloudFormation Parameters
        ######################################################################
        deployment_target = cdk.CfnParameter(
            self, 'DeploymentTarget',
            allowed_values=['opensearch_managed_cluster',
                            'opensearch_serverless'],
            # managed_cluster or serverless
            description=('Where would you like to deploy the SIEM solution? '
                         'Amazon OpenSearch managed cluster or serverless? '
                         'Serverless is experimental option'),
            default='opensearch_managed_cluster')

        domain_or_collection_name = cdk.CfnParameter(
            self, 'DomainOrCollectionName', allowed_pattern=r'^[0-9a-zA-Z_-]*',
            description=('Amazon OpenSearch Service Domain name '
                         'or OpenSearch Serverless Collection name'),
            default='aes-siem')

        vpce_id = cdk.CfnParameter(
            self, 'VpcEndpointId',
            allowed_pattern=r'(^vpce-[0-9a-z]*|aos-[0-9a-z]*|)',
            description=('(Optional) Specify VPC Endpoint for OpenSearch '
                         'managed cluster or OpenSearch Serverless. This '
                         'should be manually created before deployment. '
                         'If you specify VPC Endpoint, a few lambda functions '
                         'and other resources will be deployed into VPC'),
            default='')

        allow_source_address = cdk.CfnParameter(
            self, 'AllowedSourceIpAddresses', allowed_pattern=r'^[0-9./\s]*',
            description=('Space-delimited list of CIDR blocks. This parameter '
                         'applies only during the initial deployment'),
            default='10.0.0.0/8 172.16.0.0/12 192.168.0.0/16')

        sns_email = cdk.CfnParameter(
            self, 'SnsEmail', allowed_pattern=r'^([0-9a-zA-Z@_\-\+\.]*|)',
            description=('(Optional) '
                         'Input your email as SNS topic, where Amazon '
                         'OpenSearch Service will send alerts to'),
            default='')

        geoip_license_key = cdk.CfnParameter(
            self, 'GeoLite2LicenseKey',
            allowed_pattern=(
                r'^([0-9a-zA-Z]{6}_[0-9a-zA-Z]{29}_mmk|[0-9a-zA-Z]{16}|)$'),
            default='',
            max_length=40,
            description=("(Optional) "
                         "If you would like to enrich geoip location such as "
                         "IP address's country, get a license key from MaxMind"
                         " and input the key. "
                         "The license is a string of 16 or 40 digits"))

        trusted_proxy_list = cdk.CfnParameter(
            self, 'TrustedProxyIpList',
            allowed_pattern=r'(|[0-9a-fA-F./\s:,]*)',
            default='127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16',
            description=("(Optional) "
                         "Specify IP addresses or network addresses of "
                         "trusted Elastic Load Balancing (ELB)/ "
                         "Contents Delivery Service (CDN)/ Proxy server "
                         "other than Amazon CloudFront and AWS Global "
                         "Accelerator. Once entered, this SIEM solution will "
                         "perform an X-Forwarded-For analysis of web access "
                         "logs and select the client's IP address."))

        reserved_concurrency = cdk.CfnParameter(
            self, 'ReservedConcurrency', default=10, type='Number',
            description=('Input lambda reserved concurrency for es-loader. '
                         'Increase this value if there are steady logs delay '
                         'despite without errors'))

        otx_api_key = cdk.CfnParameter(
            self, 'OtxApiKey', allowed_pattern=r'^([0-9a-f,x]{64}|)$',
            default='', max_length=64,
            description=('(Optional) '
                         'If you would like to download IoC from AlienVault '
                         'OTX, please enter OTX API Key. '
                         'See details: https://otx.alienvault.com'))

        enable_tor = cdk.CfnParameter(
            self, 'EnableTor', allowed_values=['true', 'false'],
            description=('Would you like to download TOR IoC? '
                         'See details: https://check.torproject.org/api/bulk'),
            default='false')

        enable_abuse_ch = cdk.CfnParameter(
            self, 'EnableAbuseCh', allowed_values=['true', 'false'],
            description=(
                'Would you like to download IoC from abuse.ch? '
                'See details: https://feodotracker.abuse.ch/blocklist/'),
            default='false')

        ioc_download_interval = cdk.CfnParameter(
            self, 'IocDownloadInterval', type='Number',
            description=('Specify interval in minute to download IoC, '
                         'default is 720 minutes ( = 12 hours ).'
                         'min is 30 minutes. '
                         'max is 10080 minutes ( = 7 days ).'),
            min_value=30, max_value=10080, default=720)

        log_bucket_policy_update = cdk.CfnParameter(
            self, 'LogBucketPolicyUpdate',
            allowed_values=['update_and_override', 'keep'],
            description=(
                'Select "update_and_override" or "keep" for the current policy'
                ' of the Log bucket. Be sure to select "update_and_override" '
                'for the first deployment. If you select "update_and_override"'
                ' when updating, you need to create and manage the bucket '
                'policy for writing logs to your S3 Log bucket by yourself'),
            default='update_and_override')

        create_sqs_vpce = cdk.CfnParameter(
            self, 'CreateSqsVpcEndpoint', allowed_values=['true', 'false'],
            description=('Create new SQS VPC Endpoint with SIEM solution. '
                         'If you use existing VPC and already have SQS VPC '
                         'Endpoint, select false'),
            default='true')

        create_ssm_vpce = cdk.CfnParameter(
            self, 'CreateSsmVpcEndpoint', allowed_values=['true', 'false'],
            description=('Create new Systems Manager VPC Endpoint with SIEM '
                         'solution. If you use existing VPC and already have '
                         'Systems Manager VPC Endpoint, select false'),
            default='true')

        create_sts_vpce = cdk.CfnParameter(
            self, 'CreateStsVpcEndpoint', allowed_values=['true', 'false'],
            description=('Create new STS VPC Endpoint with SIEM solution. '
                         'If you use existing VPC and already have STS VPC '
                         'Endpoint, select false'),
            default='true')

        create_s3_vpce = cdk.CfnParameter(
            self, 'CreateS3VpcEndpoint', allowed_values=['true', 'false'],
            description=('Create new S3 VPC Endpoint with SIEM solution. '
                         'If you use existing VPC and already have S3 VPC '
                         'Endpoint, select false'),
            default='true')

        ct_log_buckets = cdk.CfnParameter(
            self, 'ControlTowerLogBucketNameList',
            type='String',
            allowed_pattern=r'^[-0-9a-z.\s,]*$',
            description=(
                'Specify S3 log bucket names in the Log Archive account. '
                'Comma separated list. '
                '(e.g., aws-controltower-logs-123456789012-us-east-1, '
                'aws-controltower-s3-access-logs-123456789012-us-east-1 )'
            ),
            default='')

        ct_role_arn = cdk.CfnParameter(
            self, 'ControlTowerRoleArnForEsLoader',
            description=(
                'Specify IAM Role ARN to be assumed by aes-siem-es-loader. '
                '(e.g., arn:aws:iam::123456789012:role/ct-role-for-siem )'),
            allowed_pattern=r'^(arn:aws.*:iam::[0-9]{12}:role/.*|)$',
            default='')

        ct_log_sqs = cdk.CfnParameter(
            self, 'ControlTowerSqsForLogBuckets',
            type='String',
            allowed_pattern=r'^(arn:aws[0-9a-zA-Z:/_-]*|)$',
            description=(
                'Specify SQS ARN for S3 log buckets in Log Archive Account. '
                '(e.g., arn:aws:sqs:us-east-1:123456789012:aes-siem-ct )'
            ),
            default='')

        sl_role_arn = cdk.CfnParameter(
            self, 'SecurityLakeRoleArn',
            description=(
                'Specify IAM Role ARN to be assumed by aes-siem-es-loader. '
                '(e.g., arn:aws:iam::123456789012:role/AmazonSecurityLake'
                '-00001111-2222-3333-5555-666677778888 )'),
            allowed_pattern=(r'^(arn:aws.*:iam::[0-9]{12}:role/AmazonSecurity'
                             r'Lake-[0-9a-f-]*|)$'),
            default='')

        sl_external_id = cdk.CfnParameter(
            self, 'SecurityLakeExternalId',
            description=(
                'Specify Security Lake external ID for cross account. '
                '(e.g., externalid123 )'),
            allowed_pattern=r'^([0-9a-zA-Z]*|)$',
            default='')

        sl_log_sqs = cdk.CfnParameter(
            self, 'SecurityLakeSubscriberSqs',
            type='String',
            allowed_pattern=(r'^(arn:aws.*:sqs:.*:[0-9]{12}:AmazonSecurity'
                             r'Lake-[0-9a-f-]*-Main-Queue|)$'),
            description=(
                'Specify SQS ARN of Security Lake Subscriber. '
                '(e.g., arn:aws:sqs:us-east-1:123456789012:AmazonSecurityLake'
                '-00001111-2222-3333-5555-666677778888-Main-Queue )'),
            default='')

        # Pretfify parameters
        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'Initial Deployment Parameters'},
                     'Parameters': [allow_source_address.logical_id]},
                    {'Label': {'default': 'Basic Configuration'},
                     'Parameters': [deployment_target.logical_id,
                                    domain_or_collection_name.logical_id,
                                    sns_email.logical_id,
                                    reserved_concurrency.logical_id]},
                    {'Label': {'default': 'Log Enrichment - optional'},
                     'Parameters': [geoip_license_key.logical_id,
                                    trusted_proxy_list.logical_id,
                                    otx_api_key.logical_id,
                                    enable_tor.logical_id,
                                    enable_abuse_ch.logical_id,
                                    ioc_download_interval.logical_id]},
                    {'Label': {'default': ('Advanced Configuration '
                                           '- optional')},
                     'Parameters': [log_bucket_policy_update.logical_id,
                                    vpce_id.logical_id,
                                    create_s3_vpce.logical_id,
                                    create_sqs_vpce.logical_id,
                                    create_ssm_vpce.logical_id,
                                    create_sts_vpce.logical_id]},
                    {'Label': {'default': ('Control Tower Integration '
                                           '- optional')},
                     'Parameters': [ct_log_buckets.logical_id,
                                    ct_log_sqs.logical_id,
                                    ct_role_arn.logical_id, ]},
                    {'Label': {'default': ('Security Lake Integration '
                                           '- optional')},
                     'Parameters': [sl_log_sqs.logical_id,
                                    sl_role_arn.logical_id,
                                    sl_external_id.logical_id, ]},
                    {'Label': {'default': 'Other parameters'},
                     'Parameters': []},
                ]
            }
        }

        cfn_parameters_dict = {
            'deployment_target': deployment_target,
            'domain_or_collection_name': domain_or_collection_name,
            'vpce_id': vpce_id,
            'allow_source_address': allow_source_address,
            'sns_email': sns_email,
            'geoip_license_key': geoip_license_key,
            'trusted_proxy_list': trusted_proxy_list,
            'reserved_concurrency': reserved_concurrency,
            'otx_api_key': otx_api_key,
            'enable_tor': enable_tor,
            'enable_abuse_ch': enable_abuse_ch,
            'ioc_download_interval': ioc_download_interval,
            'log_bucket_policy_update': log_bucket_policy_update,
            'create_sqs_vpce': create_sqs_vpce,
            'create_ssm_vpce': create_ssm_vpce,
            'create_sts_vpce': create_sts_vpce,
            'create_s3_vpce': create_s3_vpce,
            'ct_log_buckets': ct_log_buckets,
            'ct_role_arn': ct_role_arn,
            'ct_log_sqs': ct_log_sqs,
            'sl_role_arn': sl_role_arn,
            'sl_external_id': sl_external_id,
            'sl_log_sqs': sl_log_sqs,
        }

        ######################################################################
        # CDK Parameters
        ######################################################################
        solution_prefix = self.node.try_get_context('aes_domain_name')
        if solution_prefix == 'aes-siem':
            AOS_DOMAIN = domain_or_collection_name.value_as_string
        else:
            AOS_DOMAIN = solution_prefix
        bucket = f'{solution_prefix}-{cdk.Aws.ACCOUNT_ID}'
        s3bucket_name_geo = f'{bucket}-geo'
        s3bucket_name_log = f'{bucket}-log'
        s3bucket_name_snapshot = f'{bucket}-snapshot'
        cfn_ct_aws_account = cdk.Fn.select(
            4, cdk.Fn.split(':', ct_role_arn.value_as_string))
        cfn_sl_aws_account = cdk.Fn.select(
            4, cdk.Fn.split(':', sl_role_arn.value_as_string))

        # organizations / multiaccount
        org_id = self.node.try_get_context('organizations').get('org_id')
        org_mgmt_id = self.node.try_get_context(
            'organizations').get('management_id')
        org_member_ids = self.node.try_get_context(
            'organizations').get('member_ids')
        no_org_ids = self.node.try_get_context(
            'no_organizations').get('aws_accounts')
        no_org_ids.sort()

        # Overwrite default S3 bucket name as customer name
        temp_geo = self.node.try_get_context('s3_bucket_name').get('geo')
        if temp_geo:
            s3bucket_name_geo = temp_geo
        else:
            print('Using default bucket names')
        temp_log = self.node.try_get_context('s3_bucket_name').get('log')
        if temp_log:
            s3bucket_name_log = temp_log
        elif org_id or no_org_ids:
            s3bucket_name_log = f'{solution_prefix}-{self.account}-log'
        else:
            print('Using default bucket names')
        temp_snap = self.node.try_get_context('s3_bucket_name').get('snapshot')
        if temp_snap:
            s3bucket_name_snapshot = temp_snap
        else:
            print('Using default bucket names')
        kms_cmk_alias = self.node.try_get_context('kms_cmk_alias')
        if not kms_cmk_alias:
            kms_cmk_alias = 'aes-siem-key'
            print('Using default key alais')

        # vpc_type is 'new' or 'import' or None
        vpc_type = self.node.try_get_context('vpc_type')
        if vpc_type:
            is_vpc = True
        else:
            is_vpc = False

        ######################################################################
        # Cloudformation Conditions
        ######################################################################
        is_global_region = cdk.CfnCondition(
            self, "isGlobalRegion",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_or(
                    cdk.Fn.condition_equals(cdk.Aws.REGION, 'cn-north-1'),
                    cdk.Fn.condition_equals(cdk.Aws.REGION, 'cn-northwest-1'),
                    cdk.Fn.condition_equals(cdk.Aws.REGION, 'us-gov-east-1'),
                    cdk.Fn.condition_equals(cdk.Aws.REGION, 'us-gov-west-1'),
                )
            )
        )

        is_china_region = cdk.CfnCondition(
            self, "isChinaRegion",
            expression=cdk.Fn.condition_or(
                cdk.Fn.condition_equals(cdk.Aws.REGION, 'cn-north-1'),
                cdk.Fn.condition_equals(cdk.Aws.REGION, 'cn-northwest-1'),
            )
        )

        has_lambda_architectures_prop = cdk.CfnCondition(
            self, "HasLambdaArchitecturesProp",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_or(
                    cdk.Fn.condition_equals(cdk.Aws.REGION, 'ap-dummy-99'),
                    # cdk.Fn.condition_equals(cdk.Aws.REGION, 'il-central-1'),
                )
            )
        )

        is_serverless = cdk.CfnCondition(
            self, 'IsServerless',
            expression=cdk.Fn.condition_equals(
                deployment_target.value_as_string,
                'opensearch_serverless')
        )

        is_managed_cluster = cdk.CfnCondition(
            self, 'IsManagedCluster',
            expression=cdk.Fn.condition_equals(
                deployment_target.value_as_string,
                'opensearch_managed_cluster')
        )

        has_vpce = cdk.CfnCondition(
            self, "hasVpce",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(vpce_id.value_as_string, '')
            )
        )

        is_in_vpc = cdk.CfnCondition(
            self, 'IsInVpc', expression=cdk.Fn.condition_or(
                cdk.Fn.condition_equals(is_vpc, True),
                has_vpce,
            )
        )

        has_geoip_license = cdk.CfnCondition(
            self, "HasGeoipLicense",
            expression=cdk.Fn.condition_or(
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        geoip_license_key.value_as_string, '')),
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        trusted_proxy_list.value_as_string, '')),
            )
        )

        enable_ioc = cdk.CfnCondition(
            self, "EnableIOC",
            expression=cdk.Fn.condition_or(
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        otx_api_key.value_as_string, '')),
                cdk.Fn.condition_equals(
                    enable_tor.value_as_string, 'true'),
                cdk.Fn.condition_equals(
                    enable_abuse_ch.value_as_string, 'true'),
            )
        )

        has_sns_email = cdk.CfnCondition(
            self, "HasSnsEmail",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    sns_email.value_as_string, '')
            )
        )

        keep_log_bucket_policy = cdk.CfnCondition(
            self, "KeepLogBucketPolicy",
            expression=cdk.Fn.condition_equals(
                log_bucket_policy_update.value_as_string,
                'keep')
        )

        sqs_vpce_is_required = cdk.CfnCondition(
            self, "SqsVpceIsRequired",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_equals(
                    create_sqs_vpce.value_as_string, 'true'),
                is_in_vpc,
            )
        )

        ssm_vpce_is_required = cdk.CfnCondition(
            self, "SsmVpceIsRequired",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_equals(
                    create_ssm_vpce.value_as_string, 'true'),
                is_in_vpc,
            )
        )

        s3_vpce_is_required = cdk.CfnCondition(
            self, "S3VpceIsRequired",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_equals(
                    create_s3_vpce.value_as_string, 'true'),
                is_in_vpc,
            )
        )

        is_control_tower_access = cdk.CfnCondition(
            self, "IsControlTowerAcccess",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        ct_log_buckets.value_as_string, '')),
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        ct_role_arn.value_as_string, '')),
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        ct_log_sqs.value_as_string, '')),
            )
        )

        is_security_lake_access = cdk.CfnCondition(
            self, "IsSecurityLakeAcccess",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        sl_external_id.value_as_string, '')),
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        sl_role_arn.value_as_string, '')),
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        sl_log_sqs.value_as_string, '')),
            )
        )

        sts_vpce_is_required = cdk.CfnCondition(
            self, "StsVpceIsRequired",
            expression=cdk.Fn.condition_and(
                is_in_vpc,
                cdk.Fn.condition_equals(
                    create_sts_vpce.value_as_string, 'true'),
                cdk.Fn.condition_or(
                    is_control_tower_access,
                    is_security_lake_access,
                )
            )
        )

        cfn_conditions_dict = {
            'is_global_region': is_global_region,
            'is_china_region': is_china_region,
            'has_lambda_architectures_prop': has_lambda_architectures_prop,
            'is_serverless': is_serverless,
            'is_managed_cluster': is_managed_cluster,
            'has_vpce': has_vpce,
            'is_in_vpc': is_in_vpc,
            'has_geoip_license': has_geoip_license,
            'enable_ioc': enable_ioc,
            'has_sns_email': has_sns_email,
            'keep_log_bucket_policy': keep_log_bucket_policy,
            'sqs_vpce_is_required': sqs_vpce_is_required,
            'ssm_vpce_is_required': ssm_vpce_is_required,
            'sts_vpce_is_required': sts_vpce_is_required,
            's3_vpce_is_required': s3_vpce_is_required,
            'is_control_tower_access': is_control_tower_access,
            'is_security_lake_access': is_security_lake_access,
        }

        """
        CloudFormation実行時の条件式の書き方
        ClassのBasesが aws_cdk.cdk.Resource の時は、
        node.default_child.cfn_options.condition = is_in_vpc
        ClassのBasesが aws_cdk.cdk.CfnResource の時は、
        cfn_options.condition = is_in_vpc
        """

        ######################################################################
        # deploy VPC when context is defined as using VPC
        ######################################################################
        # vpc_type is 'new' or 'import' or None
        aos_vpc_id = ''
        aos_subnet_ids_raw = []
        if vpc_type == 'new':
            vpc_cidr = self.node.try_get_context('new_vpc_nw_cidr_block')
            vpc_cidr_blocks = [vpc_cidr]
            subnet_cidr_mask = int(
                self.node.try_get_context('new_vpc_subnet_cidr_mask'))
            # VPC
            vpc_aes_siem = aws_ec2.Vpc(
                self, 'VpcAesSiem',
                ip_addresses=aws_ec2.IpAddresses.cidr(vpc_cidr),
                max_azs=3, nat_gateways=0,
                subnet_configuration=[
                    aws_ec2.SubnetConfiguration(
                        subnet_type=aws_ec2.SubnetType.PRIVATE_ISOLATED,
                        name='aes-siem-subnet', cidr_mask=subnet_cidr_mask)])
            aos_subnet_ids_raw = [
                subnet.subnet_id for subnet in vpc_aes_siem.isolated_subnets]
            vpc_aes_siem_opt = vpc_aes_siem.node.default_child.cfn_options
            vpc_aes_siem_opt.deletion_policy = cdk.CfnDeletionPolicy.RETAIN
            for subnet in vpc_aes_siem.isolated_subnets:
                subnet_opt = subnet.node.default_child.cfn_options
                subnet_opt.deletion_policy = cdk.CfnDeletionPolicy.RETAIN
        elif vpc_type == 'import':
            aos_vpc_id = self.node.try_get_context('imported_vpc_id')
            vpc_aes_siem = aws_ec2.Vpc.from_lookup(
                self, 'VpcAesSiem', vpc_id=aos_vpc_id)
            boto3_vpc = ec2_resource.Vpc(aos_vpc_id)
            vpc_cidr_blocks = (
                [x['CidrBlock'] for x in boto3_vpc.cidr_block_association_set])
            aos_subnet_ids_raw = get_subnet_ids(self)

        ######################################################################
        # validate siem resource
        ######################################################################
        resource_validator = ResourceValidator(
            self, SOLUTION_NAME, PARTITION, AOS_DOMAIN,
            solution_prefix, aos_subnet_ids_raw,
            s3bucket_name_log, s3bucket_name_snapshot,
            cfn_parameters_dict, cfn_conditions_dict,
            same_lambda_func_version, region_mapping)
        validated_resource = resource_validator.validate_for_siem_deployment()

        ######################################################################
        # create cmk of KMS to encrypt S3 bucket
        ######################################################################
        kms_aes_siem = aws_kms.Key(
            self, 'KmsAesSiemLog', description='CMK for SIEM solution',
            removal_policy=cdk.RemovalPolicy.RETAIN)

        aws_kms.Alias(
            self, 'KmsAesSiemLogAlias', alias_name=kms_cmk_alias,
            target_key=kms_aes_siem,
            removal_policy=cdk.RemovalPolicy.RETAIN)

        kms_aes_siem.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid='Allow GuardDuty to use the key',
                actions=['kms:GenerateDataKey'],
                principals=[aws_iam.ServicePrincipal(
                    'guardduty.amazonaws.com')],
                resources=['*'],),)

        kms_aes_siem.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid='Allow VPC Flow Logs to use the key',
                actions=['kms:Encrypt', 'kms:Decrypt', 'kms:ReEncrypt*',
                         'kms:GenerateDataKey*', 'kms:DescribeKey'],
                principals=[aws_iam.ServicePrincipal(
                    'delivery.logs.amazonaws.com')],
                resources=['*'],),)

        # basic policy
        key_policy_basic1 = aws_iam.PolicyStatement(
            sid='Allow principals in the account to decrypt log files',
            actions=['kms:DescribeKey', 'kms:ReEncryptFrom'],
            principals=[aws_iam.AccountPrincipal(
                account_id=cdk.Aws.ACCOUNT_ID)],
            resources=['*'],)
        kms_aes_siem.add_to_resource_policy(key_policy_basic1)

        # for Athena
        key_policy_athena = aws_iam.PolicyStatement(
            sid='Allow Athena to query s3 objects with this key',
            actions=['kms:Decrypt', 'kms:DescribeKey', 'kms:Encrypt',
                     'kms:GenerateDataKey*', 'kms:ReEncrypt*'],
            principals=[aws_iam.AccountPrincipal(
                account_id=cdk.Aws.ACCOUNT_ID)],
            resources=['*'],
            conditions={'ForAnyValue:StringEquals': {
                'aws:CalledVia': 'athena.amazonaws.com'}})
        kms_aes_siem.add_to_resource_policy(key_policy_athena)

        # for CloudTrail
        key_policy_trail1 = aws_iam.PolicyStatement(
            sid='Allow CloudTrail to describe key',
            actions=['kms:DescribeKey'],
            principals=[aws_iam.ServicePrincipal('cloudtrail.amazonaws.com')],
            resources=['*'],)
        kms_aes_siem.add_to_resource_policy(key_policy_trail1)

        key_policy_trail2 = aws_iam.PolicyStatement(
            sid=('Allow CloudTrail to encrypt logs'),
            actions=['kms:GenerateDataKey*'],
            principals=[aws_iam.ServicePrincipal(
                'cloudtrail.amazonaws.com')],
            resources=['*'],
            conditions={'StringLike': {
                'kms:EncryptionContext:aws:cloudtrail:arn': [
                    (f'arn:{PARTITION}:cloudtrail:*:{cdk.Aws.ACCOUNT_ID}:'
                     'trail/*')
                ]}})
        kms_aes_siem.add_to_resource_policy(key_policy_trail2)

        ######################################################################
        # create s3 bucket
        ######################################################################
        block_pub = aws_s3.BlockPublicAccess(
            block_public_acls=True,
            ignore_public_acls=True,
            block_public_policy=True,
            restrict_public_buckets=True
        )
        s3_geo = aws_s3.Bucket(
            self, 'S3BucketForGeoip', block_public_access=block_pub,
            bucket_name=s3bucket_name_geo,
            encryption=aws_s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
        )

        # create s3 bucket for log collector
        s3_log = aws_s3.Bucket(
            self, 'S3BucketForLog', block_public_access=block_pub,
            bucket_name=s3bucket_name_log, versioned=True,
            encryption=aws_s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
        )
        s3_log.node.add_dependency(validated_resource)

        # restore current s3 bucket policy
        def ssm_get_param(log_bucket_policy_update, param_name):
            get_parameter = cr.AwsCustomResource(
                self, f's3bucket{param_name}',
                function_name='aes-siem-aws-api-caller',
                timeout=cdk.Duration.seconds(30),
                install_latest_aws_sdk=False,
                on_update=cr.AwsSdkCall(
                    service="SSM",
                    action="getParameter",
                    output_paths=["Parameter.Value"],
                    parameters={
                        "Name": f'/siem/bucketpolicy/log/{param_name}',
                        "WithDecryption": False},
                    physical_resource_id=cr.PhysicalResourceId.of(
                        f"CustomResource::{param_name}-{__version__}-"
                        f"{log_bucket_policy_update.value_as_string}")
                ),
                policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                    resources=[(f'arn:{PARTITION}:ssm:*:{cdk.Aws.ACCOUNT_ID}:'
                                'parameter/siem/bucketpolicy/*')]
                ),
            )
            get_parameter.node.add_dependency(validated_resource)
            return get_parameter.get_response_field("Parameter.Value")

        pol1 = ssm_get_param(log_bucket_policy_update, "policy1")
        pol2 = ssm_get_param(log_bucket_policy_update, "policy2")
        pol3 = ssm_get_param(log_bucket_policy_update, "policy3")
        pol4 = ssm_get_param(log_bucket_policy_update, "policy4")
        pol5 = ssm_get_param(log_bucket_policy_update, "policy5")
        pol6 = ssm_get_param(log_bucket_policy_update, "policy6")
        pol7 = ssm_get_param(log_bucket_policy_update, "policy7")
        pol8 = ssm_get_param(log_bucket_policy_update, "policy8")
        s3_log_bucket_policy = cdk.Fn.join(
            '', [pol1, pol2, pol3, pol4, pol5, pol6, pol7, pol8])

        s3_log.policy.node.default_child.add_property_override(
            "PolicyDocument",
            cdk.Fn.condition_if(
                keep_log_bucket_policy.logical_id,
                s3_log_bucket_policy,
                s3_log.policy.document
            )
        )

        # create s3 bucket for aes snapshot
        s3_snapshot = aws_s3.Bucket(
            self, 'S3BucketForSnapshot', block_public_access=block_pub,
            bucket_name=s3bucket_name_snapshot,
            encryption=aws_s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
        )

        ######################################################################
        # IAM Role
        ######################################################################
        # snapshot policy for AOS
        policydoc_snapshot = aws_iam.PolicyDocument(
            statements=[
                aws_iam.PolicyStatement(
                    actions=['s3:ListBucket'],
                    resources=[s3_snapshot.bucket_arn]
                ),
                aws_iam.PolicyStatement(
                    actions=['s3:GetObject', 's3:PutObject',
                             's3:DeleteObject'],
                    resources=[s3_snapshot.bucket_arn + '/*']
                )
            ]
        )
        aes_siem_snapshot_role = aws_iam.Role(
            self, 'AesSiemSnapshotRole',
            role_name='aes-siem-snapshot-role',
            inline_policies={'s3access': policydoc_snapshot},
            assumed_by=aws_iam.ServicePrincipal(
                'opensearchservice.amazonaws.com')
        )

        # for alert from Amazon OpenSearch Service
        aes_siem_sns_role = aws_iam.Role(
            self, 'AesSiemSnsRole',
            role_name='aes-siem-sns-role',
            assumed_by=aws_iam.ServicePrincipal(
                'opensearchservice.amazonaws.com')
        )
        kms_aes_siem.grant(
            aes_siem_sns_role,
            'kms:Decrypt', 'kms:GenerateDataKey'
        )
        kms_aes_siem.grant(
            aws_iam.ServicePrincipal('events.amazonaws.com'),
            'kms:Decrypt', 'kms:GenerateDataKey'
        )

        # EC2 role
        if self.region.startswith('cn-'):
            ec2_sp = 'ec2.amazonaws.com.cn'
        else:
            ec2_sp = 'ec2.amazonaws.com'
        aes_siem_es_loader_ec2_role = aws_iam.Role(
            self, 'AesSiemEsLoaderEC2Role',
            role_name='aes-siem-es-loader-for-ec2',
            assumed_by=aws_iam.ServicePrincipal(ec2_sp),
        )

        aes_siem_es_loader_ec2_role.add_to_principal_policy(
            aws_iam.PolicyStatement(
                # for vpc access
                actions=["ec2:CreateNetworkInterface",
                         "ec2:DescribeNetworkInterfaces",
                         "ec2:DeleteNetworkInterface",
                         "ec2:AssignPrivateIpAddresses",
                         "ec2:UnassignPrivateIpAddresses"],
                resources=['*']
            )
        )

        aws_iam.CfnInstanceProfile(
            self, 'AesSiemEsLoaderEC2InstanceProfile',
            instance_profile_name=aes_siem_es_loader_ec2_role.role_name,
            roles=[aes_siem_es_loader_ec2_role.role_name]
        )

        aes_role_exist = check_iam_role(
            '/aws-service-role/opensearchservice.amazonaws.com/')
        if vpc_type and not aes_role_exist:
            slr_aes = aws_iam.CfnServiceLinkedRole(
                self, 'AWSServiceRoleForAmazonOpenSearchService',
                aws_service_name='opensearchservice.amazonaws.com',
                description='Created by cloudformation of siem stack'
            )
            slr_aes.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

        ######################################################################
        # Resource in VPC (SecurityGroup and PrivateLink)
        ######################################################################
        # Security Group for VPC
        sg_vpc_noinbound_aes_siem = aws_ec2.CfnSecurityGroup(
            self, "AesSiemVpcNoinboundSecurityGroup58555CE0",
            # group_name="aes-siem-noinbound-vpc-sg",
            group_description="aes-siem/AesSiemVpcNoinboundSecurityGroup",
            vpc_id=validated_resource.get_att('vpc_id').to_string(),
        )
        sg_vpc_noinbound_aes_siem.cfn_options.condition = is_in_vpc
        sg_vpc_noinbound_aes_siem.apply_removal_policy(
            cdk.RemovalPolicy.RETAIN)

        # security group for aos managed cluster in vpc
        if vpc_type and not aos_sg_is_associated:
            sg_vpc_aes_siem = aws_ec2.SecurityGroup(
                self, 'AesSiemVpcSecurityGroup',
                security_group_name='aes-siem-vpc-sg',
                vpc=vpc_aes_siem)
            for vpc_cidr_block in vpc_cidr_blocks:
                sg_vpc_aes_siem.add_ingress_rule(
                    peer=aws_ec2.Peer.ipv4(vpc_cidr_block),
                    connection=aws_ec2.Port.tcp(443),)
            sg_vpc_opt = sg_vpc_aes_siem.node.default_child.cfn_options
            sg_vpc_opt.deletion_policy = cdk.CfnDeletionPolicy.RETAIN
        else:
            sg_vpc_aes_siem = None

            """
            sg_vpc_aes_siem = aws_ec2.CfnSecurityGroup(
                self, "AesSiemVpcSecurityGroupC784BBE6",
                group_name="aes-siem-vpc-sg",
                group_description="aes-siem/AesSiemVpcSecurityGroup",
                vpc_id=validated_resource.get_att('vpc_id').to_string(),
                security_group_ingress=[
                    aws_ec2.CfnSecurityGroup.IngressProperty(
                        cidr_ip=validated_resource.get_att('cidr_block0').to_string(),
                        ip_protocol="tcp", from_port=443, to_port=443),
                ]
            )
            sg_vpc_aes_siem.cfn_options.condition = is_in_vpc
            sg_vpc_aes_siem.apply_removal_policy(cdk.RemovalPolicy.RETAIN)
            """

        sg_vpc_aes_siem2 = aws_ec2.CfnSecurityGroup(
            self, "AesSiemVpcSecurityGroup2nd",
            group_name="aes-siem-vpc-sg2",
            group_description="aes-siem/AesSiemVpcSecurityGroup2nd",
            vpc_id=validated_resource.get_att('vpc_id').to_string(),
            security_group_ingress=[
                aws_ec2.CfnSecurityGroup.IngressProperty(
                    cidr_ip=validated_resource.get_att(
                        'cidr_block0').to_string(),
                    ip_protocol="tcp", from_port=443, to_port=443),
                aws_ec2.CfnSecurityGroup.IngressProperty(
                    cidr_ip=validated_resource.get_att(
                        'cidr_block1').to_string(),
                    ip_protocol="tcp", from_port=443, to_port=443),
                aws_ec2.CfnSecurityGroup.IngressProperty(
                    cidr_ip=validated_resource.get_att(
                        'cidr_block2').to_string(),
                    ip_protocol="tcp", from_port=443, to_port=443),
                aws_ec2.CfnSecurityGroup.IngressProperty(
                    cidr_ip=validated_resource.get_att(
                        'cidr_block3').to_string(),
                    ip_protocol="tcp", from_port=443, to_port=443),
            ]
        )
        sg_vpc_aes_siem2.cfn_options.condition = is_in_vpc

        # VPC Endpoint
        vpce_endpoint_sqs = aws_ec2.CfnVPCEndpoint(
            self, "VpcAesSiemSQSEndpoint8BFF7847", vpc_id='', subnet_ids=[],
            vpc_endpoint_type="Interface",
            private_dns_enabled=True,
            security_group_ids=[sg_vpc_aes_siem2.attr_group_id],
            service_name=f"com.amazonaws.{cdk.Aws.REGION}.sqs",
        )
        vpce_endpoint_sqs.add_property_override(
            "VpcId", validated_resource.get_att('vpc_id').to_string())
        vpce_endpoint_sqs.add_property_override(
            "SubnetIds", validated_resource.get_att('subnets').to_string())
        vpce_endpoint_sqs.cfn_options.condition = sqs_vpce_is_required
        vpce_endpoint_sqs.add_property_override(
            "ServiceName",
            cdk.Fn.condition_if(
                is_china_region.logical_id,
                f"cn.com.amazonaws.{cdk.Aws.REGION}.sqs",
                f"com.amazonaws.{cdk.Aws.REGION}.sqs",
            )
        )

        vpce_endpoint_ssm = aws_ec2.CfnVPCEndpoint(
            self, "VpcAesSiemSSMEndpoint", vpc_id='', subnet_ids=[],
            vpc_endpoint_type="Interface",
            private_dns_enabled=True,
            security_group_ids=[sg_vpc_aes_siem2.attr_group_id],
            service_name=f"com.amazonaws.{cdk.Aws.REGION}.ssm",
        )
        vpce_endpoint_ssm.add_property_override(
            "VpcId", validated_resource.get_att('vpc_id').to_string())
        vpce_endpoint_ssm.add_property_override(
            "SubnetIds", validated_resource.get_att('subnets').to_string())
        vpce_endpoint_ssm.cfn_options.condition = ssm_vpce_is_required

        vpce_endpoint_sts = aws_ec2.CfnVPCEndpoint(
            self, "VpcAesSiemSTSEndpoint", vpc_id='', subnet_ids=[],
            vpc_endpoint_type="Interface",
            private_dns_enabled=True,
            security_group_ids=[sg_vpc_aes_siem2.attr_group_id],
            service_name=f"com.amazonaws.{cdk.Aws.REGION}.sts",
        )
        vpce_endpoint_sts.add_property_override(
            "VpcId", validated_resource.get_att('vpc_id').to_string())
        vpce_endpoint_sts.add_property_override(
            "SubnetIds", validated_resource.get_att('subnets').to_string())
        vpce_endpoint_sts.cfn_options.condition = sts_vpce_is_required
        vpce_endpoint_sts.add_property_override(
            "ServiceName",
            cdk.Fn.condition_if(
                is_china_region.logical_id,
                f"cn.com.amazonaws.{cdk.Aws.REGION}.sts",
                f"com.amazonaws.{cdk.Aws.REGION}.sts",
            )
        )

        vpce_endpoint_s3 = aws_ec2.CfnVPCEndpoint(
            self, "VpcAesSiemS3Endpoint003F70DF", vpc_id='',
            vpc_endpoint_type="Gateway",
            service_name=f"com.amazonaws.{cdk.Aws.REGION}.s3",
        )
        vpce_endpoint_s3.add_property_override(
            "VpcId", validated_resource.get_att('vpc_id').to_string())
        vpce_endpoint_s3.add_property_override(
            "RouteTableIds",
            validated_resource.get_att('route_table_ids').to_string())
        vpce_endpoint_s3.cfn_options.condition = s3_vpce_is_required

        ######################################################################
        # SQS for es-laoder's DLQ
        ######################################################################
        sqs_aes_siem_dlq = aws_sqs.Queue(
            self, 'AesSiemDlq', queue_name='aes-siem-dlq',
            encryption=aws_sqs.QueueEncryption.KMS_MANAGED,
            data_key_reuse=cdk.Duration.hours(24),
            retention_period=cdk.Duration.days(14))

        sqs_aes_siem_splitted_logs = aws_sqs.Queue(
            self, 'AesSiemSqsSplitLogs',
            queue_name='aes-siem-sqs-splitted-logs',
            encryption=aws_sqs.QueueEncryption.KMS_MANAGED,
            data_key_reuse=cdk.Duration.hours(24),
            dead_letter_queue=aws_sqs.DeadLetterQueue(
                max_receive_count=20, queue=sqs_aes_siem_dlq),
            visibility_timeout=cdk.Duration.seconds(ES_LOADER_TIMEOUT * 6),
            retention_period=cdk.Duration.days(14))

        ######################################################################
        # Setup Lambda
        ######################################################################
        # setup lambda of es_loader
        function_name = 'aes-siem-es-loader'
        lambda_es_loader = aws_lambda.Function(
            self, 'LambdaEsLoader',
            function_name=function_name,
            description=f'{SOLUTION_NAME} / es-loader',
            runtime=aws_lambda.Runtime.PYTHON_3_11,
            code=aws_lambda.Code.from_asset('../lambda/es_loader'),
            handler='index.lambda_handler',
            memory_size=2048,
            initial_policy=[
                aws_iam.PolicyStatement(
                    # for vpc access
                    actions=["ec2:CreateNetworkInterface",
                             "ec2:DescribeNetworkInterfaces",
                             "ec2:DeleteNetworkInterface",
                             "ec2:AssignPrivateIpAddresses",
                             "ec2:UnassignPrivateIpAddresses"],
                    resources=['*']
                )
            ],
            timeout=cdk.Duration.seconds(ES_LOADER_TIMEOUT),
            reserved_concurrent_executions=(
                reserved_concurrency.value_as_number),
            dead_letter_queue_enabled=True,
            dead_letter_queue=sqs_aes_siem_dlq,
            environment={
                'GEOIP_BUCKET': s3bucket_name_geo, 'LOG_LEVEL': 'info',
                'POWERTOOLS_LOGGER_LOG_EVENT': 'false',
                'POWERTOOLS_SERVICE_NAME': 'es-loader',
                'POWERTOOLS_METRICS_NAMESPACE': 'SIEM',
                'CONTROL_TOWER_ROLE_SESSION_NAME': 'aes-siem-es-loader',
                'CONTROL_TOWER_ROLE_ARN': ct_role_arn.value_as_string,
                'CONTROL_TOWER_LOG_BUCKETS': ct_log_buckets.value_as_string,
                'SECURITY_LAKE_ROLE_SESSION_NAME': 'aes-siem-es-loader',
                'SECURITY_LAKE_ROLE_ARN': sl_role_arn.value_as_string,
                'SECURITY_LAKE_EXTERNAL_ID': (
                    sl_external_id.value_as_string),
            },
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__
            ),
        )
        if not same_lambda_func_version(function_name):
            lambda_es_loader.current_version
        lambda_es_loader.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                has_lambda_architectures_prop.logical_id,
                [region_mapping.find_in_map(cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        lambda_es_loader.node.default_child.add_property_override(
            "VpcConfig.SubnetIds",
            validated_resource.get_att('subnets').to_string()
        )
        lambda_es_loader.node.default_child.add_property_override(
            "VpcConfig.SecurityGroupIds",
            cdk.Fn.condition_if(
                is_in_vpc.logical_id,
                [sg_vpc_noinbound_aes_siem.attr_group_id],
                []
            )
        )

        sqs_aes_siem_dlq.grant(
            lambda_es_loader, 'sqs:SendMessage', 'sqs:ReceiveMessage',
            'sqs:DeleteMessage', 'sqs:GetQueueAttributes')

        sqs_aes_siem_splitted_logs.grant(
            lambda_es_loader, 'sqs:SendMessage', 'sqs:ReceiveMessage',
            'sqs:DeleteMessage', 'sqs:GetQueueAttributes')

        lambda_es_loader.add_event_source(
            aws_lambda_event_sources.SqsEventSource(
                sqs_aes_siem_splitted_logs, batch_size=1))
        lambda_es_loader.node.default_child.add_property_override(
            "VpcConfig.SubnetIds",
            validated_resource.get_att('subnets').to_string()
        )
        lambda_es_loader.node.default_child.add_property_override(
            "VpcConfig.SecurityGroupIds",
            cdk.Fn.condition_if(
                is_in_vpc.logical_id,
                [sg_vpc_noinbound_aes_siem.attr_group_id],
                []
            )
        )
        # lambda_es_loader.node.add_dependency(sg_vpc_noinbound_aes_siem)

        # es-loaer on EC2 role
        sqs_aes_siem_dlq.grant(
            aes_siem_es_loader_ec2_role, 'sqs:GetQueue*', 'sqs:ListQueues*',
            'sqs:ReceiveMessage*', 'sqs:DeleteMessage*')

        ######################################################################
        # Setup Helper Lambda functions
        ######################################################################
        helper_lambda_function = HelperLambdaFunctions(
            self, SOLUTION_NAME, PARTITION, AOS_DOMAIN,
            INDEX_METRICS_PERIOD_HOUR, validated_resource, s3bucket_name_geo,
            s3bucket_name_log, same_lambda_func_version, cfn_parameters_dict,
            cfn_conditions_dict, lambda_es_loader, sg_vpc_noinbound_aes_siem,
            region_mapping)
        lambda_add_pandas_layer = (
            helper_lambda_function.create_lambda_add_pandas_layer())

        lambda_es_loader_stopper = (
            helper_lambda_function.create_lambda_es_loader_stopper())

        lambda_metrics_exporter = (
            helper_lambda_function.create_lambda_metrics_exporter())

        enrich = Enrichment(
            self, SOLUTION_NAME, s3bucket_name_geo, same_lambda_func_version,
            cfn_parameters_dict, cfn_conditions_dict, region_mapping)
        lambda_geo = enrich.setup_geoip()
        lambda_ioc_plan, lambda_ioc_download, lambda_ioc_createdb = (
            enrich.setup_ioc())

        ######################################################################
        # setup OpenSearch Service Managed Cluster / Serverless
        ######################################################################
        aos = AosDeployment(
            self, SOLUTION_NAME, PARTITION, AOS_DOMAIN, validated_resource,
            solution_prefix, vpc_type, aos_sg_is_associated,
            aos_subnet_ids_raw, same_lambda_func_version,
            cfn_parameters_dict, cfn_conditions_dict,
            aes_siem_snapshot_role, s3_snapshot, lambda_metrics_exporter,
            lambda_es_loader, sg_vpc_aes_siem, sg_vpc_noinbound_aes_siem,
            region_mapping)
        aos_deployment_result = aos.setup_domain_or_collection()

        endpoint = aos_deployment_result['endpoint']
        aoss_type = aos_deployment_result['aoss_type']
        aos_domain_arn = aos_deployment_result['aos_domain_arn']
        collection_arn = aos_deployment_result['collection_arn']
        kibana_admin_user = aos_deployment_result['kibana_admin_user']
        kibana_admin_pass = aos_deployment_result['kibana_admin_pass']
        deploy_role_arn = aos_deployment_result['deploy_role_arn']

        lambda_es_loader.add_environment('ENDPOINT', endpoint)
        lambda_es_loader.add_environment('AOSS_TYPE', aoss_type)
        lambda_es_loader.add_environment(
            'SQS_SPLITTED_LOGS_URL', sqs_aes_siem_splitted_logs.queue_url)
        lambda_metrics_exporter.add_environment('ENDPOINT', endpoint)

        # grant permission to es_loader role
        inline_policy_to_load_entries_into_aos = aws_iam.Policy(
            self, 'aes-siem-policy-to-load-entries-to-es',
            policy_name='aes-siem-policy-to-load-entries-to-es',
            statements=[
                aws_iam.PolicyStatement(
                    actions=['es:ESHttp*'],
                    resources=[f'{aos_domain_arn}/*']
                ),
                aws_iam.PolicyStatement(
                    actions=['aoss:APIAccessAll'],
                    resources=[collection_arn]
                ),
            ]
        )
        lambda_es_loader.role.attach_inline_policy(
            inline_policy_to_load_entries_into_aos)
        aes_siem_es_loader_ec2_role.attach_inline_policy(
            inline_policy_to_load_entries_into_aos)
        lambda_metrics_exporter.role.attach_inline_policy(
            inline_policy_to_load_entries_into_aos)

        inline_policy_to_get_parameters_by_path = aws_iam.Policy(
            self, 'aes-siem-policy-to-get-parameters-by-path',
            policy_name='aes-siem-policy-to-get-parameters-by-path',
            statements=[
                aws_iam.PolicyStatement(
                    actions=['ssm:GetParametersByPath'],
                    resources=[
                        f'arn:{PARTITION}:ssm:*:{cdk.Aws.ACCOUNT_ID}:'
                        'parameter/siem/exclude-logs/*'
                    ]),
            ]
        )
        lambda_es_loader.role.attach_inline_policy(
            inline_policy_to_get_parameters_by_path)
        aes_siem_es_loader_ec2_role.attach_inline_policy(
            inline_policy_to_get_parameters_by_path)

        # grant additional permission to es_loader role
        additional_kms_cmks = self.node.try_get_context('additional_kms_cmks')
        if additional_kms_cmks:
            inline_policy_access_to_additional_cmks = aws_iam.Policy(
                self, 'access_to_additional_cmks',
                policy_name='access_to_additional_cmks',
                statements=[
                    aws_iam.PolicyStatement(
                        actions=['kms:Decrypt'],
                        resources=sorted(set(additional_kms_cmks))
                    )
                ]
            )
            lambda_es_loader.role.attach_inline_policy(
                inline_policy_access_to_additional_cmks)
            aes_siem_es_loader_ec2_role.attach_inline_policy(
                inline_policy_access_to_additional_cmks)
        additional_buckets = self.node.try_get_context('additional_s3_buckets')

        if additional_buckets:
            buckets_list = []
            for bucket in additional_buckets:
                buckets_list.append(f'arn:{PARTITION}:s3:::{bucket}')
                buckets_list.append(f'arn:{PARTITION}:s3:::{bucket}/*')
            inline_policy_access_to_additional_buckets = aws_iam.Policy(
                self, 'access_to_additional_buckets',
                policy_name='access_to_additional_buckets',
                statements=[
                    aws_iam.PolicyStatement(
                        actions=['s3:GetObject*', 's3:GetBucket*', 's3:List*'],
                        resources=sorted(set(buckets_list))
                    )
                ]
            )
            lambda_es_loader.role.attach_inline_policy(
                inline_policy_access_to_additional_buckets)
            aes_siem_es_loader_ec2_role.attach_inline_policy(
                inline_policy_access_to_additional_buckets)

        kms_aes_siem.grant_decrypt(lambda_es_loader)
        kms_aes_siem.grant_decrypt(aes_siem_es_loader_ec2_role)
        kms_aes_siem.grant_encrypt(lambda_metrics_exporter)

        ######################################################################
        # s3 notification and grant permisssion
        ######################################################################
        s3_geo.grant_read_write(lambda_geo)
        s3_geo.grant_read_write(lambda_add_pandas_layer)
        s3_geo.grant_read_write(lambda_ioc_plan)
        s3_geo.grant_read_write(lambda_ioc_download)
        s3_geo.grant_read_write(lambda_ioc_createdb)
        s3_geo.grant_read(lambda_es_loader)
        s3_geo.grant_read(aes_siem_es_loader_ec2_role)
        s3_log.grant_read(lambda_es_loader)
        s3_log.grant_read(aes_siem_es_loader_ec2_role)
        s3_log.grant_write(lambda_metrics_exporter)

        # create s3 notification for es_loader
        notification = aws_s3_notifications.LambdaDestination(lambda_es_loader)

        # assign notification for the s3 PUT event type
        # most log system use PUT, but also CLB use POST & Multipart Upload
        s3_log.add_event_notification(
            aws_s3.EventType.OBJECT_CREATED, notification)

        ######################################################################
        # bucket policy
        ######################################################################
        # ALB, CLB
        s3_awspath = f'{s3_log.bucket_arn}/AWSLogs/{cdk.Aws.ACCOUNT_ID}'
        s3_awspath_w_prefix = (
            f'{s3_log.bucket_arn}/*/AWSLogs/{cdk.Aws.ACCOUNT_ID}')
        bucket_policy_alb1 = aws_iam.PolicyStatement(
            sid='ALB,CLB Policy',
            principals=[
                aws_iam.AccountPrincipal(
                    account_id=region_mapping.find_in_map(
                        cdk.Aws.REGION, 'ElbV2AccountId')),
            ],
            actions=['s3:PutObject'],
            resources=[f'{s3_awspath}/*', f'{s3_awspath_w_prefix}/*'],
        )
        bucket_policy_alb2 = aws_iam.PolicyStatement(
            sid='Policy For no ALB account region',
            principals=[
                aws_iam.ServicePrincipal(
                    'logdelivery.elasticloadbalancing.amazonaws.com')
            ],
            actions=['s3:PutObject'],
            resources=[f'{s3_log.bucket_arn}/*'],
            conditions={
                "StringEquals": {"aws:SourceAccount": [cdk.Aws.ACCOUNT_ID]}
            }
        )
        if self.region not in no_alb_log_account_list:
            s3_log.add_to_resource_policy(bucket_policy_alb1)
        else:
            s3_log.add_to_resource_policy(bucket_policy_alb2)

        # NLB / R53resolver / VPC Flow Logs
        bucket_policy_logdeliver1 = aws_iam.PolicyStatement(
            sid='AWSLogDelivery For NLB,R53Resolver,Flowlogs',
            principals=[aws_iam.ServicePrincipal(
                'delivery.logs.amazonaws.com')],
            actions=['s3:GetBucketAcl', 's3:ListBucket', 's3:PutObject'],
            resources=[s3_log.bucket_arn, f'{s3_log.bucket_arn}/*'],
            conditions={
                "StringEquals": {"aws:SourceAccount": [cdk.Aws.ACCOUNT_ID]}
            }
        )
        s3_log.add_to_resource_policy(bucket_policy_logdeliver1)

        # CloudTrail / Config
        bucket_policy_trail1 = aws_iam.PolicyStatement(
            sid='AWSLogDeliveryAclCheck For Cloudtrail, Config',
            principals=[
                aws_iam.ServicePrincipal('cloudtrail.amazonaws.com'),
                aws_iam.ServicePrincipal('config.amazonaws.com'),
            ],
            actions=['s3:GetBucketAcl', 's3:ListBucket'],
            resources=[s3_log.bucket_arn],
        )
        bucket_policy_trail2 = aws_iam.PolicyStatement(
            sid='AWSLogDeliveryWrite For CloudTrail, Config',
            principals=[
                aws_iam.ServicePrincipal('cloudtrail.amazonaws.com'),
                aws_iam.ServicePrincipal('config.amazonaws.com')],
            actions=['s3:PutObject'],
            resources=[f'{s3_log.bucket_arn}/*/*'],
            conditions={
                'StringEquals': {
                    "aws:SourceAccount": [cdk.Aws.ACCOUNT_ID],
                }
            }
        )
        s3_log.add_to_resource_policy(bucket_policy_trail1)
        s3_log.add_to_resource_policy(bucket_policy_trail2)

        # GuardDuty
        bucket_policy_gd1 = aws_iam.PolicyStatement(
            sid='Allow GuardDuty to put objects',
            principals=[aws_iam.ServicePrincipal('guardduty.amazonaws.com')],
            actions=['s3:GetBucketLocation', 's3:PutObject'],
            resources=[s3_log.bucket_arn, f'{s3_log.bucket_arn}/*'],
            conditions={
                'StringEquals': {"aws:SourceAccount": [cdk.Aws.ACCOUNT_ID]}
            }
        )
        s3_log.add_to_resource_policy(bucket_policy_gd1)

        # for IOC
        s3_geo.add_lifecycle_rule(
            enabled=True,
            expiration=cdk.Duration.days(8),
            noncurrent_version_expiration=cdk.Duration.days(8),
            id="delete-ioc-temp-files",
            prefix='IOC/tmp/'
        )

        # OpenSearch Doamin Snapshot
        bucket_policy_snapshot = aws_iam.PolicyStatement(
            sid='Allow OpenSearch Service to store snapshot',
            principals=[aes_siem_snapshot_role],
            actions=['s3:PutObject', 's3:GetObject', 's3:DeleteObject'],
            resources=[s3_snapshot.bucket_arn + '/*'],)
        s3_snapshot.add_to_resource_policy(bucket_policy_snapshot)

        ######################################################################
        # for multiaccount / organizaitons
        ######################################################################
        if org_id or no_org_ids:
            ##################################################################
            # KMS key policy for multiaccount / organizaitons
            ##################################################################
            # for CloudTrail
            cond_tail2 = self.make_resource_list(
                path=f'arn:{PARTITION}:cloudtrail:*:', tail=':trail/*',
                keys=self.list_without_none(org_mgmt_id, no_org_ids))
            key_policy_mul_trail2 = aws_iam.PolicyStatement(
                sid=('Allow CloudTrail to encrypt logs for multiaccounts'),
                actions=['kms:GenerateDataKey*'],
                principals=[aws_iam.ServicePrincipal(
                    'cloudtrail.amazonaws.com')],
                resources=['*'],
                conditions={'StringLike': {
                    'kms:EncryptionContext:aws:cloudtrail:arn': cond_tail2}})
            kms_aes_siem.add_to_resource_policy(key_policy_mul_trail2)

            # for replicaiton
            key_policy_rep1 = aws_iam.PolicyStatement(
                sid=('Enable cross account encrypt access for S3 Cross Region '
                     'Replication'),
                actions=['kms:Encrypt'],
                principals=self.make_account_principals(
                    org_mgmt_id, org_member_ids, no_org_ids),
                resources=['*'],)
            kms_aes_siem.add_to_resource_policy(key_policy_rep1)

            ##################################################################
            # Buckdet Policy for multiaccount / organizaitons
            ##################################################################
            s3_log_bucket_arn = f'arn:{PARTITION}:s3:::{s3bucket_name_log}'
            all_aws_accounts = self.list_without_none(
                org_mgmt_id, org_member_ids, no_org_ids)

            # for CloudTrail / Config
            if org_id:
                bucket_policy_org_trail1 = aws_iam.PolicyStatement(
                    sid='AWSCloudTrail, Config Write for Organizations',
                    principals=[
                        aws_iam.ServicePrincipal('cloudtrail.amazonaws.com'),
                        aws_iam.ServicePrincipal('config.amazonaws.com'),
                    ],
                    actions=['s3:PutObject'],
                    resources=[
                        f'{s3_log_bucket_arn}/{org_id}/AWSLogs/*/*',
                        f'{s3_log_bucket_arn}/*/{org_id}/AWSLogs/*/*',
                    ],
                )
                s3_log.add_to_resource_policy(bucket_policy_org_trail1)
            if len(no_org_ids) > 0:
                bucket_policy_org_trail2 = aws_iam.PolicyStatement(
                    sid='AWSCloudTrailWrite, Config for not org Multiaccounts',
                    principals=[
                        aws_iam.ServicePrincipal('cloudtrail.amazonaws.com'),
                        aws_iam.ServicePrincipal('config.amazonaws.com'),
                    ],
                    actions=['s3:PutObject'],
                    resources=[f'{s3_log_bucket_arn}/*/*'],
                    conditions={
                        'StringEquals': {"aws:SourceAccount": no_org_ids}
                    }
                )
                s3_log.add_to_resource_policy(bucket_policy_org_trail2)

            # for ALB
            resouces_list = self.make_resource_prefix_list(
                arn=s3_log_bucket_arn, tail='*', keys=all_aws_accounts)
            bucket_policy_mul_alb1 = aws_iam.PolicyStatement(
                sid='ALB,CLB multi Policy',
                principals=[
                    aws_iam.AccountPrincipal(
                        account_id=region_mapping.find_in_map(
                            cdk.Aws.REGION, 'ElbV2AccountId')),
                ],
                actions=['s3:PutObject'],
                resources=resouces_list,
            )
            # for no ALB account
            bucket_policy_mul_alb2 = aws_iam.PolicyStatement(
                sid='Policy for no ALB account for multiaccount',
                principals=[
                    aws_iam.ServicePrincipal(
                        'logdelivery.elasticloadbalancing.amazonaws.com')
                ],
                actions=['s3:PutObject'],
                resources=[f'{s3_log.bucket_arn}/*'],
                conditions={
                    "StringEquals": {"aws:SourceAccount": all_aws_accounts}
                }
            )
            if self.region not in no_alb_log_account_list:
                s3_log.add_to_resource_policy(bucket_policy_mul_alb1)
            else:
                s3_log.add_to_resource_policy(bucket_policy_mul_alb2)

            # NLB / R53resolver / VPC Flow Logs
            bucket_policy_mul_logdeliver1 = aws_iam.PolicyStatement(
                sid='AWSLogDeliveryAclCheck For mul NLB R53Resolver Flowlogs',
                principals=[aws_iam.ServicePrincipal(
                    'delivery.logs.amazonaws.com')],
                actions=['s3:GetBucketAcl', 's3:ListBucket', 's3:PutObject'],
                resources=[s3_log.bucket_arn, f'{s3_log.bucket_arn}/*'],
                conditions={
                    "StringEquals": {"aws:SourceAccount": all_aws_accounts}
                }
            )
            s3_log.add_to_resource_policy(bucket_policy_mul_logdeliver1)

            # for replication
            bucket_policy_rep1 = aws_iam.PolicyStatement(
                sid='PolicyForDestinationBucket / Permissions on objects',
                principals=self.make_account_principals(
                    org_mgmt_id, org_member_ids, no_org_ids),
                actions=['s3:ReplicateDelete', 's3:ReplicateObject',
                         's3:ReplicateTags', 's3:GetObjectVersionTagging',
                         's3:ObjectOwnerOverrideToBucketOwner'],
                resources=[f'{s3_log_bucket_arn}/*'])
            bucket_policy_rep2 = aws_iam.PolicyStatement(
                sid='PolicyForDestinationBucket / Permissions on bucket',
                principals=self.make_account_principals(
                    org_mgmt_id, org_member_ids, no_org_ids),
                actions=['s3:List*', 's3:GetBucketVersioning',
                         's3:PutBucketVersioning'],
                resources=[f'{s3_log_bucket_arn}'])
            s3_log.add_to_resource_policy(bucket_policy_rep1)
            s3_log.add_to_resource_policy(bucket_policy_rep2)

        ######################################################################
        # SNS topic for Amazon OpenSearch Service Alert
        ######################################################################
        sns_topic = aws_sns.Topic(
            self, 'SnsTopic', topic_name='aes-siem-alert',
            master_key=kms_aes_siem,
            display_name='AES SIEM')
        sns_topic.grant_publish(aes_siem_sns_role)
        sns_topic.grant_publish(lambda_es_loader_stopper)

        sns_subscription = aws_sns.Subscription(
            self, "SnsTopicTokenSubscription",
            topic=sns_topic,
            endpoint=sns_email.value_as_string,
            protocol=aws_sns.SubscriptionProtocol.EMAIL,
        )
        sns_subscription.node.default_child.cfn_options.condition = (
            has_sns_email)

        # setup Amazon OpenSearch Service monitoring notify
        aos_notifications_rule = aws_events.Rule(
            self, "EventBridgeRuleAosNotifications",
            enabled=True,
            event_pattern=aws_events.EventPattern(
                source=['aws.es'],
                resources=[aos_domain_arn]
            ),
            targets=[aws_events_targets.SnsTopic(sns_topic)],
        )
        aos_notifications_rule.node.default_child.cfn_options.condition = (
            has_sns_email)

        ######################################################################
        # Control Tower
        ######################################################################
        # grant additional permission to es_loader role for control tower
        inline_policy_controltower = aws_iam.Policy(
            self, 'access_to_control_tower_log_buckets',
            policy_name='access_to_control_tower',
            statements=[
                aws_iam.PolicyStatement(
                    actions=['sts:AssumeRole'],
                    resources=[ct_role_arn.value_as_string],
                ),
                aws_iam.PolicyStatement(
                    actions=[
                        "sqs:ReceiveMessage",
                        "sqs:ChangeMessageVisibility",
                        "sqs:GetQueueUrl",
                        "sqs:DeleteMessage",
                        "sqs:GetQueueAttributes"
                    ],
                    resources=[
                        (f'arn:{PARTITION}:sqs:*:{cfn_ct_aws_account}:*')],
                )
            ]
        )
        inline_policy_controltower.node.default_child.cfn_options.condition = (
            is_control_tower_access)
        lambda_es_loader.role.attach_inline_policy(
            inline_policy_controltower)
        aes_siem_es_loader_ec2_role.attach_inline_policy(
            inline_policy_controltower)

        source_mapping_for_ct = aws_lambda.EventSourceMapping(
            self, "EventSourceMappingForCT",
            target=lambda_es_loader,
            event_source_arn=ct_log_sqs.value_as_string,
            report_batch_item_failures=True,
        )
        source_mapping_for_ct.node.default_child.cfn_options.condition = (
            is_control_tower_access)

        ######################################################################
        # Amazon Security Lake
        ######################################################################
        # grant additional permission to es_loader role for control tower
        inline_policy_securitylake = aws_iam.Policy(
            self, 'access_to_security_lake_log_buckets',
            policy_name='access_to_security_lake',
            statements=[
                aws_iam.PolicyStatement(
                    actions=['sts:AssumeRole'],
                    resources=[sl_role_arn.value_as_string],
                ),
                aws_iam.PolicyStatement(
                    actions=[
                        "sqs:ReceiveMessage",
                        "sqs:ChangeMessageVisibility",
                        "sqs:GetQueueUrl",
                        "sqs:DeleteMessage",
                        "sqs:GetQueueAttributes"
                    ],
                    resources=[
                        (f'arn:{PARTITION}:sqs:*:{cfn_sl_aws_account}:*')],
                )
            ]
        )
        inline_policy_securitylake.node.default_child.cfn_options.condition = (
            is_security_lake_access)
        lambda_es_loader.role.attach_inline_policy(
            inline_policy_securitylake)
        aes_siem_es_loader_ec2_role.attach_inline_policy(
            inline_policy_securitylake)

        source_mapping_for_ct2 = aws_lambda.EventSourceMapping(
            self, "EventSourceMappingForCT2",
            target=lambda_es_loader,
            event_source_arn=sl_log_sqs.value_as_string,
            report_batch_item_failures=True,
        )
        source_mapping_for_ct2.node.default_child.cfn_options.condition = (
            is_security_lake_access)

        ######################################################################
        # CloudWatch
        ######################################################################
        # alarm by lambda_es_loader_stopper
        total_free_storage_space_remains_low_alarm = (
            helper_lambda_function.create_alarm_es_loader_stopper(
                sns_topic.topic_arn))

        cw_dashbaord = CloudWatchDashboardSiem(
            self, AOS_DOMAIN, endpoint, cfn_conditions_dict,
            lambda_es_loader, sqs_aes_siem_splitted_logs, sqs_aes_siem_dlq,
            total_free_storage_space_remains_low_alarm,
        )
        cw_dashbaord.create_cloudwatch_dashboard()

        ######################################################################
        # output of CFn
        ######################################################################
        kibanaurl = f'https://{endpoint}/_dashboards/'
        kibanaadmin = kibana_admin_user
        kibanapass = kibana_admin_pass

        cdk.CfnOutput(self, 'RoleDeploy', export_name='role-deploy',
                      value=deploy_role_arn)
        cdk.CfnOutput(self, 'DashboardsUrl', export_name='dashboards-url',
                      value=kibanaurl)
        cdk.CfnOutput(self, 'DashboardsPassword',
                      export_name='dashboards-pass', value=kibanapass,
                      description=('Please change the password in OpenSearch '
                                   'Dashboards ASAP'))
        cdk.CfnOutput(self, 'DashboardsAdminID',
                      export_name='dashboards-admin', value=kibanaadmin)

    def list_without_none(self, *args):
        list_args = []
        for arg in args:
            if not arg:
                pass
            elif isinstance(arg, str) and arg:
                list_args.append(arg)
            elif isinstance(arg, list) and len(arg) > 0:
                list_args.extend(arg)
        list_args = sorted(list(set(list_args)))
        try:
            list_args.remove('')
        except Exception:
            # pass
            # to ignore Rule-269212
            None
        return list_args

    def make_account_principals(self, *args):
        aws_ids = self.list_without_none(*args)
        account_principals = []
        for aws_id in sorted(set(aws_ids)):
            account_principals.append(
                aws_iam.AccountPrincipal(account_id=aws_id))
        return account_principals

    def make_resource_list(self, path=None, tail=None, keys=[]):
        aws_ids = self.list_without_none(keys)
        multi_s3path = []
        for aws_id in sorted(set(aws_ids)):
            multi_s3path.append(path + aws_id + tail)
        return multi_s3path

    def make_resource_prefix_list(self, arn=None, tail=None, keys=[]):
        aws_ids = self.list_without_none(keys)
        multi_s3path = []
        for aws_id in sorted(set(aws_ids)):
            multi_s3path.append(f'{arn}/AWSLogs/{aws_id}/{tail}')
            multi_s3path.append(f'{arn}/*/AWSLogs/{aws_id}/{tail}')
        return multi_s3path
