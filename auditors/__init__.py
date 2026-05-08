import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound

def get_session(profile, region):
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        # Test the connection
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        return session, identity
    except ProfileNotFound:
        return None, f"AWS profile '{profile}' not found"
    except NoCredentialsError:
        return None, "No AWS credentials found"
    except Exception as e:
        return None, str(e)