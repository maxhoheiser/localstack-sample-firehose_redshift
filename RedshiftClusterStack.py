import os

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_iam as iam
import aws_cdk.aws_redshift as redshift
from constructs import Construct
from dotenv import load_dotenv

load_dotenv()


redshift_master_user = os.environ.get("REDSHIFT_MASTER_USER")
redshift_master_password = os.environ.get("REDSHIFT_MASTER_PW")
redshift_db_name = os.environ.get("REDSHIFT_DB_NAME")
redshift_cluster_name = os.environ.get("REDSHIFT_CLUSTER_NAME")
redshift_default_port = os.environ.get("REDSHIFT_DEFAULT_PORT")


class RedshiftClusterStack(cdk.Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Create Redshift cluster VPC
        self.redshift_vpc = ec2.Vpc(
            self,
            "RedshiftVpc",
            vpc_name="redshift-vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.10.0.0/16"),  # cidr="10.10.0.0.0/16"
            max_azs=2,
            nat_gateways=0,
            enable_dns_support=True,
            enable_dns_hostnames=True,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public", cidr_mask=24, subnet_type=ec2.SubnetType.PUBLIC
                ),
                ec2.SubnetConfiguration(
                    name="db", cidr_mask=24, subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
                ),
            ],
        )

        # Create Redshift cluster role
        role_redshift_cluster = iam.Role(
            self,
            "RedshiftClusterRole",
            role_name="redshift-cluster-role",
            assumed_by=iam.ServicePrincipal("redshift.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3ReadOnlyAccess")
            ],
        )

        redshift_vpc_subnet_ids = self.redshift_vpc.select_subnets(
            subnet_type=ec2.SubnetType.PUBLIC
        ).subnet_ids

        # create subnet group for cluster
        redshift_cluster_subnet_group = redshift.CfnClusterSubnetGroup(
            self,
            "RedshiftClusterSubnetGroup",
            subnet_ids=redshift_vpc_subnet_ids,
            description="Redshift Cluster Subnet Group",
        )

        # create redshift cluster
        ec2_instance_type = "dc2.large"
        self.redshift_cluster = redshift.CfnCluster(
            self,
            "RedshiftCluster",
            cluster_identifier=redshift_cluster_name,
            cluster_type="single-node",
            number_of_nodes=1,
            db_name=redshift_db_name,
            master_username=redshift_master_user,
            master_user_password=redshift_master_password,
            iam_roles=[role_redshift_cluster.role_arn],
            node_type=f"{ec2_instance_type}",
            cluster_subnet_group_name=redshift_cluster_subnet_group.ref,
            publicly_accessible=True,
        )
