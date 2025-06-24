import boto3

from library.aws.models.iam_models import PasswordPolicy

def get_password_policy(connection: boto3.Session) -> PasswordPolicy:
    """Get the password policy for the AWS account.

    Args:
        connection (boto3.Session): The boto3 session to use.

    Returns:
        PasswordPolicy: The password policy for the AWS account.
    """
    response = connection.client('iam').get_account_password_policy()
    
    password_policy = response['PasswordPolicy']
    
    return PasswordPolicy(
        minimum_password_length=password_policy['MinimumPasswordLength'],
        require_symbols=password_policy['RequireSymbols'],
        require_numbers=password_policy['RequireNumbers'],
        require_uppercase_characters=password_policy['RequireUppercaseCharacters'],
        require_lowercase_characters=password_policy['RequireLowercaseCharacters'],
        allow_users_to_change_password=password_policy['AllowUsersToChangePassword'],
        expire_passwords=password_policy['ExpirePasswords'],
        max_password_age=password_policy['MaxPasswordAge'],
        password_reuse_prevention=password_policy['PasswordReusePrevention'],
        hard_expiry=password_policy['HardExpiry']
    )
