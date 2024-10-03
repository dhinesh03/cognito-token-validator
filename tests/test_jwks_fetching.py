# JWKS Fetching Test Cases
import pytest
from unittest.mock import patch
from cognito_token_validator.validator import TokenValidator

# Verify that the JWKS is fetched correctly from the AWS Cognito endpoint when the TokenValidator is initialized.


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
def test_token_validator_jwks_fetching(mock_fetch_jwks):
    mock_fetch_jwks.return_value = {"keys": []}

    TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",
        get_auth_header=lambda: "Bearer test_token"
    )

    mock_fetch_jwks.assert_called_once()  # Ensure JWKS is fetched on initialization

# Verify behavior when JWKS fetching fails (e.g., network issues). Ensure a RuntimeError is raised if the JWKS cannot be fetched.


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
def test_token_validator_jwks_fetch_failure(mock_fetch_jwks):
    mock_fetch_jwks.side_effect = RuntimeError("Failed to fetch JWKS")

    with pytest.raises(RuntimeError, match="Failed to fetch JWKS"):
        TokenValidator(
            region="us-east-1",
            user_pool_id="test_pool",
            client_id="test_client",
            get_auth_header=lambda: "Bearer test_token"
        )
    mock_fetch_jwks.assert_called_once()
