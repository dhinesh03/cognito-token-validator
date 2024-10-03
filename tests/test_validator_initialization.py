# Initialization Test Cases
from unittest.mock import patch
from cognito_token_validator.validator import TokenValidator


# Verify that the TokenValidator is initialized with the correct values for region, user_pool_id, client_id, and whitelisted_emails.


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
def test_token_validator_initialization(mock_fetch_jwks):
    # Mock the JWKS fetching
    mock_fetch_jwks.return_value = {"keys": []}

    validator = TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",
        get_auth_header=lambda: "Bearer test_token",
        whitelisted_emails=["user@example.com"]
    )

    assert validator.region == "us-east-1"
    assert validator.user_pool_id == "test_pool"
    assert validator.client_id == "test_client"
    assert validator.whitelisted_emails == ["user@example.com"]
    mock_fetch_jwks.assert_called_once()

# Verify that the default values for cache_max_size and ttl are set correctly if not provided during initialization.


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
def test_token_validator_default_cache_values(mock_fetch_jwks):
    mock_fetch_jwks.return_value = {"keys": []}

    validator = TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",
        get_auth_header=lambda: "Bearer test_token"
    )

    assert validator.token_cache.maxsize == 10  # Default cache size
    assert validator.token_cache.ttl == 3600  # Default TTL
    mock_fetch_jwks.assert_called_once()

# Verify that the whitelisted_emails are properly converted to lowercase during initialization.


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
def test_token_validator_whitelisted_emails_lowercase(mock_fetch_jwks):
    mock_fetch_jwks.return_value = {"keys": []}

    validator = TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",
        get_auth_header=lambda: "Bearer test_token",
        whitelisted_emails=["USER1@example.com", "USER2@EXAMPLE.COM"]
    )

    assert validator.whitelisted_emails == ["user1@example.com", "user2@example.com"]
    mock_fetch_jwks.assert_called_once()

# Verify that the token_cache is initialized correctly with the provided cache_max_size and ttl.


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
def test_token_validator_custom_cache_values(mock_fetch_jwks):
    mock_fetch_jwks.return_value = {"keys": []}

    validator = TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",
        get_auth_header=lambda: "Bearer test_token",
        cache_max_size=20,
        ttl=1800
    )

    assert validator.token_cache.maxsize == 20  # Custom cache size
    assert validator.token_cache.ttl == 1800  # Custom TTL
    mock_fetch_jwks.assert_called_once()
