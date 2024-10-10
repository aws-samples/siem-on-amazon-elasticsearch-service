# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import aws_cdk as cdk
from aws_cdk import (
    aws_cloudformation,
    aws_cloudwatch,
    aws_events,
    aws_events_targets,
    aws_iam,
    aws_lambda,
)


class HelperLambdaFunctions(object):
    def __init__(self, scope, SOLUTION_NAME: str, PARTITION: str,
                 AOS_DOMAIN: str, INDEX_METRICS_PERIOD_HOUR: str,
                 validated_resource,
                 s3bucket_name_geo: str, s3bucket_name_log: str,
                 same_lambda_func_version,
                 cfn_parameters_dict: dict, cfn_conditions_dict: dict,
                 lambda_es_loader, sg_vpc_noinbound_aes_siem, region_mapping):

        self.scope = scope
        self.SOLUTION_NAME = SOLUTION_NAME
        self.PARTITION = PARTITION
        self.AOS_DOMAIN = AOS_DOMAIN
        self.INDEX_METRICS_PERIOD_HOUR = INDEX_METRICS_PERIOD_HOUR
        self.validated_resource = validated_resource
        self.reserved_concurrency = cfn_parameters_dict['reserved_concurrency']
        self.domain_or_collection_name = (
            cfn_parameters_dict['domain_or_collection_name'])
        self.has_lambda_architectures_prop = (
            cfn_conditions_dict['has_lambda_architectures_prop'])
        self.is_global_region = cfn_conditions_dict['is_global_region']
        self.is_in_vpc = cfn_conditions_dict['is_in_vpc']
        self.s3bucket_name_geo = s3bucket_name_geo
        self.s3bucket_name_log = s3bucket_name_log
        self.same_lambda_func_version = same_lambda_func_version
        self.lambda_es_loader = lambda_es_loader
        self.sg_vpc_noinbound_aes_siem = sg_vpc_noinbound_aes_siem
        self.region_mapping = region_mapping

    def create_lambda_add_pandas_layer(self):
        function_name = 'aes-siem-add-pandas-layer'
        arn_pan = [
            f'arn:{self.PARTITION}:lambda:*:*:layer:AWSDataWrangler-*',
            f'arn:{self.PARTITION}:lambda:*:*:layer:AWSSDKPandas-*',
        ]
        lambda_add_pandas_layer_role = aws_iam.Role(
            self.scope, "LambdaAddPandasLayerRole",
            managed_policies=[
                aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                    'service-role/AWSLambdaBasicExecutionRole')],
            inline_policies={
                'add-pandas-layer-policy': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            actions=['lambda:UpdateFunctionConfiguration',
                                     'lambda:GetFunction',
                                     'lambda:ListTags'],
                            resources=[self.lambda_es_loader.function_arn]),
                        aws_iam.PolicyStatement(
                            actions=['lambda:PublishLayerVersion'],
                            resources=arn_pan,),
                        aws_iam.PolicyStatement(
                            actions=['lambda:ListLayers',
                                     'lambda:GetLayerVersion'],
                            resources=['*']),
                        aws_iam.PolicyStatement(
                            actions=["s3:Get*", "s3:List*"],
                            resources=['*']
                        )])},
            assumed_by=aws_iam.ServicePrincipal('lambda.amazonaws.com')
        )
        lambda_add_pandas_layer = aws_lambda.Function(
            self.scope, 'LambdaAddPandasLayer',
            function_name=function_name,
            description=f'{self.SOLUTION_NAME} / add-pandas-layer',
            runtime=aws_lambda.Runtime.PYTHON_3_11,
            code=aws_lambda.Code.from_asset('../lambda/add_pandas_layer'),
            handler='lambda_function.lambda_handler',
            memory_size=128,
            timeout=cdk.Duration.seconds(300),
            reserved_concurrent_executions=1,
            environment={
                'GEOIP_BUCKET': self.s3bucket_name_geo
            },
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__
            ),
            role=lambda_add_pandas_layer_role,
        )
        if not self.same_lambda_func_version(function_name):
            lambda_add_pandas_layer.current_version
        lambda_add_pandas_layer.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                self.has_lambda_architectures_prop.logical_id,
                [self.region_mapping.find_in_map(
                    cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        # lambda_add_pandas_layer.node.default_child.add_property_override(
        #    "Runtime", cdk.Fn.condition_if(
        #        self.is_global_region.logical_id, 'python3.10', 'python3.9'))

        # add pandas layer by execute cfn custom resource
        excec_lambda_add_layer = aws_cloudformation.CfnCustomResource(
            self.scope, 'ExecLambdaAddPandasLayer',
            service_token=lambda_add_pandas_layer.function_arn,)
        excec_lambda_add_layer.add_override(
            'Properties.ConfigVersion', __version__)
        excec_lambda_add_layer.cfn_options.deletion_policy = (
            cdk.CfnDeletionPolicy.RETAIN)
        excec_lambda_add_layer.node.add_dependency(self.lambda_es_loader)
        excec_lambda_add_layer.node.add_dependency(
            lambda_add_pandas_layer_role)

        return lambda_add_pandas_layer

    def create_lambda_es_loader_stopper(self):
        # setup lambda of es_loader_stopper
        function_name = 'aes-siem-es-loader-stopper'
        self.lambda_es_loader_stopper = aws_lambda.Function(
            self.scope, 'LambdaEsLoaderStopper',
            function_name=function_name,
            description=f'{self.SOLUTION_NAME} / es-loader-stopper',
            runtime=aws_lambda.Runtime.PYTHON_3_11,
            code=aws_lambda.Code.from_asset('../lambda/es_loader_stopper'),
            handler='index.lambda_handler',
            memory_size=128,
            timeout=cdk.Duration.seconds(300),
            reserved_concurrent_executions=1,
            environment={
                'ES_LOADER_FUNCTION_ARN': self.lambda_es_loader.function_arn,
                'ES_LOADER_RESERVED_CONCURRENCY': (
                    self.reserved_concurrency.value_as_string)
            },
            initial_policy=[
                aws_iam.PolicyStatement(
                    actions=['lambda:PutFunctionConcurrency'],
                    resources=[self.lambda_es_loader.function_arn],
                ),
            ],
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__
            ),
        )
        if not self.same_lambda_func_version(function_name):
            self.lambda_es_loader_stopper.current_version
        self.lambda_es_loader_stopper.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                self.has_lambda_architectures_prop.logical_id,
                [self.region_mapping.find_in_map(
                    cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        # lambda_es_loader_stopper.node.default_child.add_property_override(
        #    "Runtime", cdk.Fn.condition_if(
        #        self.is_global_region.logical_id, 'python3.10', 'python3.9'))

        return self.lambda_es_loader_stopper

    def create_alarm_es_loader_stopper(self, sns_topic_arn: str):
        # Add environment variables
        self.lambda_es_loader_stopper.add_environment(
            'AES_SIEM_ALERT_TOPIC_ARN', sns_topic_arn)
        # CloudWatch Alarm
        total_free_storage_space_metric = aws_cloudwatch.Metric(
            metric_name='FreeStorageSpace', namespace='AWS/ES',
            statistic='Sum', period=cdk.Duration.minutes(1),
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID})
        total_free_storage_space_remains_low_alarm = aws_cloudwatch.Alarm(
            self.scope, 'TotalFreeStorageSpaceRemainsLowAlarm',
            alarm_description=('Triggered when total free space for the '
                               'cluster remains less 200MB for 30 minutes.'),
            metric=total_free_storage_space_metric,
            evaluation_periods=30, threshold=200,  # 200 MByte
            comparison_operator=aws_cloudwatch
            .ComparisonOperator.LESS_THAN_OR_EQUAL_TO_THRESHOLD)

        # EventBridge
        es_loader_stopper_rule = aws_events.Rule(
            self.scope, "EsLoaderStopperRule",
            event_pattern=aws_events.EventPattern(
                source=["aws.cloudwatch"],
                detail_type=["CloudWatch Alarm State Change"],
                resources=[
                    total_free_storage_space_remains_low_alarm.alarm_arn
                ]
            )
        )
        es_loader_stopper_rule.add_target(
            aws_events_targets.LambdaFunction(self.lambda_es_loader_stopper))

        return total_free_storage_space_remains_low_alarm

    def create_lambda_metrics_exporter(self):
        function_name = 'aes-siem-index-metrics-exporter'
        initial_policy = [
            aws_iam.PolicyStatement(
                # for vpc access
                sid='ForVpcAccess',
                actions=[
                    "ec2:CreateNetworkInterface",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DeleteNetworkInterface",
                    "ec2:AssignPrivateIpAddresses",
                    "ec2:UnassignPrivateIpAddresses"
                ],
                resources=['*']
            )
        ]
        lambda_metrics_exporter = aws_lambda.Function(
            self.scope, 'LambdaMetricsExporter',
            function_name=function_name,
            description=f'{self.SOLUTION_NAME} / index-metrics-exporter',
            runtime=aws_lambda.Runtime.PYTHON_3_11,
            code=aws_lambda.Code.from_asset(
                '../lambda/index_metrics_exporter'),
            handler='index.lambda_handler',
            memory_size=256,
            timeout=cdk.Duration.seconds(300),
            reserved_concurrent_executions=1,
            initial_policy=initial_policy,
            environment={
                'LOG_BUCKET': self.s3bucket_name_log,
                'PERIOD_HOUR': str(self.INDEX_METRICS_PERIOD_HOUR),
                'COLLECTION_NAME': (
                    self.domain_or_collection_name.value_as_string),
            },
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__),
        )
        if not self.same_lambda_func_version(function_name):
            lambda_metrics_exporter.current_version
        lambda_metrics_exporter.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                self.has_lambda_architectures_prop.logical_id,
                [self.region_mapping.find_in_map(
                    cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        lambda_metrics_exporter.node.default_child.add_property_override(
            "VpcConfig.SubnetIds",
            self.validated_resource.get_att('subnets').to_string()
        )
        lambda_metrics_exporter.node.default_child.add_property_override(
            "VpcConfig.SecurityGroupIds",
            cdk.Fn.condition_if(
                self.is_in_vpc.logical_id,
                [self.sg_vpc_noinbound_aes_siem.attr_group_id],
                []
            )
        )
        # lambda_metrics_exporter.node.default_child.add_property_override(
        #    "Runtime", cdk.Fn.condition_if(
        #        self.is_global_region.logical_id, 'python3.10', 'python3.9'))
        # lambda_metrics_exporter.node.add_dependency(
        #     self.sg_vpc_noinbound_aes_siem)

        # EventBridge Rules
        # collect index metrics every 1 hour
        rule_metrics_exporter = aws_events.Rule(
            self.scope, 'EventBridgeRuleLambdaMetricsExporter',
            schedule=aws_events.Schedule.rate(
                cdk.Duration.hours(self.INDEX_METRICS_PERIOD_HOUR)))
        rule_metrics_exporter.add_target(
            aws_events_targets.LambdaFunction(lambda_metrics_exporter))

        return lambda_metrics_exporter
