import aws_cdk as cdk

from FirehoseStack import FirehoseStack
from RedshiftClusterStack import RedshiftClusterStack

app = cdk.App()

redshift_cluster_stack = RedshiftClusterStack(app, "RedshiftClusterStack")

cluster_address = redshift_cluster_stack.redshift_cluster.attr_endpoint_address
firehose_stack = FirehoseStack(
    app,
    "FirehoseStack",
    cluster_address=cluster_address,
)

app.synth()
