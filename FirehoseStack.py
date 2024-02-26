import aws_cdk as cdk
import aws_cdk.aws_iam as iam
import aws_cdk.aws_kinesis as kinesis
import aws_cdk.aws_kinesisfirehose as firehose
import aws_cdk.aws_logs as logs
import aws_cdk.aws_s3 as s3
from constructs import Construct

from RedshiftClusterStack import (
    REDSHIFT_DB_NAME,
    REDSHIFT_DEFAULT_PORT,
    redshift_master_password,
    redshift_master_user,
)


class FirehoseStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        cluster_address: str,
        **kwargs,
    ) -> None:
        super().__init__(scope, id, **kwargs)

        # create kinesis stream
        kinesis_stream = kinesis.Stream(
            self,
            "KinesisStream",
            stream_name="kinesis-stream",
            shard_count=1,
            stream_mode=kinesis.StreamMode("PROVISIONED"),
        )

        # s3 bucket
        self.bucket = s3.Bucket(
            self,
            "S3Bucket",
            bucket_name="firehose-raw-data",
            removal_policy=cdk.RemovalPolicy.DESTROY,  # required since default value is RETAIN
            # auto_delete_objects=True,  # required to delete the not empty bucket
            # auto_delete requires lambda therefore not supported currently by Localstack
        )

        # create firehose delivery stream
        role_firehose_kinesis = iam.Role(
            self,
            "FirehoseKinesisRole",
            role_name="firehose-kinesis-role",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
        )
        policy_firehose_kinesis = iam.Policy(
            self,
            "FirehoseKinesisPolicy",
            policy_name="firehose-kinesis-policy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "kinesis:DescribeStream",
                        "kinesis:GetShardIterator",
                        "kinesis:GetRecords",
                        "kinesis:ListShards",
                    ],
                    resources=[kinesis_stream.stream_arn],
                ),
            ],
        )
        role_firehose_kinesis.attach_inline_policy(policy_firehose_kinesis)

        kinesis_stream_source_configuration = (
            firehose.CfnDeliveryStream.KinesisStreamSourceConfigurationProperty(
                kinesis_stream_arn=kinesis_stream.stream_arn,
                role_arn=role_firehose_kinesis.role_arn,
            )
        )

        # cloud watch logging group and stream for firehose s3 error logging
        firehose_s3_log_group_name = "firehose-s3-log-group"
        firehose_s3_log_group = logs.LogGroup(
            self,
            "FirehoseLogGroup",
            log_group_name=firehose_s3_log_group_name,
            removal_policy=cdk.RemovalPolicy.DESTROY,  # required since default value is RETAIN
        )
        # create log stream
        firehose_s3_log_stream_name = "firehose-s3-log-stream"
        logs.LogStream(
            self,
            "FirehoseLogStream",
            log_group=firehose_s3_log_group,
            log_stream_name=firehose_s3_log_stream_name,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        # s3 access role for firehose
        role_firehose_s3 = iam.Role(
            self,
            "FirehoseS3Role",
            role_name="firehose-s3-role",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
        )
        policy_firehose_s3 = iam.Policy(
            self,
            "FirehoseS3Policy",
            policy_name="firehose-s3-policy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:AbortMultipartUpload",
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:PutObject",
                    ],
                    resources=[self.bucket.bucket_arn, f"{self.bucket.bucket_arn}/*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["logs:PutLogEvents", "logs:CreateLogStream"],
                    resources=[firehose_s3_log_group.log_group_arn],
                ),
            ],
        )
        role_firehose_s3.attach_inline_policy(policy_firehose_s3)

        extended_s3_destination_configuration = firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
            bucket_arn=self.bucket.bucket_arn,
            role_arn=role_firehose_s3.role_arn,
            prefix="firehose-raw-data/",
            error_output_prefix="firehose-raw-data/errors/",
            compression_format="UNCOMPRESSED",
            s3_backup_mode="Disabled",
            buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                interval_in_seconds=1, size_in_m_bs=1
            ),
            encryption_configuration=firehose.CfnDeliveryStream.EncryptionConfigurationProperty(
                no_encryption_config="NoEncryption"
            ),
            cloud_watch_logging_options=firehose.CfnDeliveryStream.CloudWatchLoggingOptionsProperty(
                enabled=True,
                log_group_name=firehose_s3_log_group_name,
                log_stream_name=firehose_s3_log_stream_name,
            ),
        )

        # firehose redshift destination configuration
        redshift_s3_destination_configuration = (
            firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=self.bucket.bucket_arn,
                role_arn=role_firehose_s3.role_arn,
                prefix="redshift-raw-data/",
                compression_format="UNCOMPRESSED",
            )
        )

        # Get the endpoint address of the redshift cluster
        redshift_destination_configuration = firehose.CfnDeliveryStream.RedshiftDestinationConfigurationProperty(
            cluster_jdbcurl=f"jdbc:redshift://{cluster_address}:{REDSHIFT_DEFAULT_PORT}/{REDSHIFT_DB_NAME}",
            copy_command=firehose.CfnDeliveryStream.CopyCommandProperty(
                data_table_name="dataTableName"
            ),
            password=redshift_master_password,
            username=redshift_master_user,
            role_arn=role_firehose_s3.role_arn,
            s3_configuration=redshift_s3_destination_configuration,
            cloud_watch_logging_options=firehose.CfnDeliveryStream.CloudWatchLoggingOptionsProperty(
                enabled=True,
                log_group_name=firehose_s3_log_group_name,
                log_stream_name=firehose_s3_log_stream_name,
            ),
        )

        self.firehose_stream = firehose.CfnDeliveryStream(
            self,
            "FirehoseDeliveryStream",
            delivery_stream_name="firehose-deliverystream",
            delivery_stream_type="KinesisStreamAsSource",
            kinesis_stream_source_configuration=kinesis_stream_source_configuration,
            extended_s3_destination_configuration=extended_s3_destination_configuration,
            redshift_destination_configuration=redshift_destination_configuration,
        )
