import boto3
from urllib.parse import urlparse

def check_s3_permissions(url):
    parsed = urlparse(url)
    bucket = parsed.netloc.split('.')[0]
    s3 = boto3.client("s3")

    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        grants = acl.get("Grants", [])
        for grant in grants:
            if "AllUsers" in str(grant):
                return "Public Read/Write"
        return "Private or Restricted"
    except Exception as e:
        return f"Error: {str(e)}"