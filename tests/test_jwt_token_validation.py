

import logging
import pytest
from unittest.mock import patch, MagicMock
from cognito_token_validator.validator import TokenValidator
from jose import jwt, JWTError

# Verify that the validate_token method can successfully validate a valid JWT token.

# Mock a complete JWKS key
mock_jwks = {
    "keys": [{
        "kid": "mock_kid",  # Key ID
        "kty": "RSA",
        "alg": "RS256",  # Algorithm used for signing
        "n": "mock_modulus",  # Modulus (base64url encoded)
        "e": "AQAB"  # Exponent (base64url encoded)
    }]
}

# Mock the key verification function or method


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
@patch('cognito_token_validator.validator.jwt.get_unverified_header')
@patch('cognito_token_validator.validator.jwt.get_unverified_claims')  # Correct method for extracting claims
@patch('cognito_token_validator.validator.jwk.construct')  # Correctly mock the JWK signature verification
def test_token_validator_validate_valid_token(mock_construct, mock_get_unverified_claims, mock_get_unverified_header, mock_fetch_jwks):
    # Mock JWKS fetching and token header decoding
    mock_fetch_jwks.return_value = mock_jwks

    # Correctly mock the return value of get_unverified_header
    # This header should contain at least 'kid' and 'alg'
    mock_get_unverified_header.return_value = {
        "kid": "mock_kid",  # This must match the 'kid' in JWKS
        "alg": "RS256"      # Algorithm used to sign the token
    }

    # Ensure the mocked get_unverified_claims method returns the expected claims, including 'aud'
    mock_get_unverified_claims.return_value = {
        "aud": "test_client",  # Audience should match the client_id
        "sub": "user123",      # The subject (user identifier)
        "email": "user@example.com",  # User's email
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_testpool",  # Issuer (Cognito URL)
        "exp": 9999999999      # Token expiration time (epoch timestamp)
    }

    # Mock the construct method (JWK verification process) to return a valid key that passes verification
    mock_key = MagicMock()
    mock_key.verify.return_value = True  # Simulate passing verification
    mock_construct.return_value = mock_key

    # Initialize the TokenValidator
    validator = TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",  # This must match the 'aud' claim in the token
        get_auth_header=lambda: "Bearer test_token"
    )

    # Use a valid Base64URL-encoded and padded mock JWT token
    token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1vY2tfa2lkIn0.eyJjbGllbnRfaWQiOiJ0ZXN0X2NsaWVudCIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSJ9.c2lnbmF0dXJl"

    # Call the validate_token method
    result = validator.validate_token(token)

    # Ensure that mock_construct is called (signature verification is bypassed)
    mock_construct.assert_called_once()

    # Check if the get_unverified_claims method was called and result is not None
    assert result is not None, "validate_token returned None, but expected a dict with claims"
    assert result["aud"] == "test_client"  # Ensure 'aud' claim matches client_id
    assert result["email"] == "user@example.com"
    mock_get_unverified_claims.assert_called_once()
    mock_get_unverified_header.assert_called_once()

# Verify that the validate_token method raises an error for an expired JWT token.


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
@patch('cognito_token_validator.validator.jwt.get_unverified_header')
@patch('cognito_token_validator.validator.jwt.get_unverified_claims')  # Correct method for extracting claims
@patch('cognito_token_validator.validator.jwk.construct')  # Correctly mock the JWK signature verification
def test_token_validator_validate_expired_token_logs_warning(mock_construct, mock_get_unverified_claims, mock_get_unverified_header, mock_fetch_jwks, caplog):
    # Mock JWKS fetching and token header decoding
    mock_fetch_jwks.return_value = mock_jwks

    # Correctly mock the return value of get_unverified_header
    mock_get_unverified_header.return_value = {
        "kid": "mock_kid",  # This must match the 'kid' in JWKS
        "alg": "RS256"      # Algorithm used to sign the token
    }

    # Mock the unverified claims (JWT payload)
    mock_get_unverified_claims.return_value = {
        "aud": "test_client",  # Audience should match the client_id
        "sub": "user123",
        "email": "user@example.com",
        "exp": 1  # Expired token
    }

    # Mock the construct method (JWK verification process) to return a valid key that passes verification
    mock_key = MagicMock()
    mock_key.verify.return_value = True  # Simulate passing verification
    mock_construct.return_value = mock_key

    # Initialize the TokenValidator
    validator = TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",
        get_auth_header=lambda: "Bearer test_token"
    )

    # Use a valid Base64URL-encoded and padded mock JWT token
    token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1vY2tfa2lkIn0.eyJjbGllbnRfaWQiOiJ0ZXN0X2NsaWVudCIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSJ9.c2lnbmF0dXJl"

    # Enable logging capture
    with caplog.at_level(logging.INFO):
        result = validator.validate_token(token)

    # Ensure that the token validation logged a "Token is expired" message
    assert "Token is expired" in caplog.text

    # Ensure that validate_token returns None for an expired token
    assert result is None

    # Ensure that mock_construct is called
    mock_construct.assert_called_once()


# Verify that the validate_token method raises an error if the JWT token signature is invalid.


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
@patch('cognito_token_validator.validator.jwt.get_unverified_header')
@patch('cognito_token_validator.validator.jwt.get_unverified_claims')  # Correct method for extracting claims
@patch('cognito_token_validator.validator.jwk.construct')  # Correctly mock the JWK signature verification
def test_token_validator_validate_invalid_signature_logs_error(mock_construct, mock_get_unverified_claims, mock_get_unverified_header, mock_fetch_jwks, caplog):
    # Mock JWKS fetching and token header decoding
    mock_fetch_jwks.return_value = mock_jwks

    # Correctly mock the return value of get_unverified_header
    mock_get_unverified_header.return_value = {
        "kid": "mock_kid",  # This must match the 'kid' in JWKS
        "alg": "RS256"      # Algorithm used to sign the token
    }

    # Mock the unverified claims (JWT payload)
    mock_get_unverified_claims.return_value = {
        "aud": "test_client",  # Audience should match the client_id
        "sub": "user123",
        "email": "user@example.com"
    }

    # Mock the construct method (JWK verification process) to return a key that fails verification
    mock_key = MagicMock()
    mock_key.verify.side_effect = JWTError("Invalid token signature")  # Simulate verification failure
    mock_construct.return_value = mock_key

    # Initialize the TokenValidator
    validator = TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",
        get_auth_header=lambda: "Bearer test_token"
    )

    # Use a valid Base64URL-encoded and padded mock JWT token
    token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1vY2tfa2lkIn0.eyJjbGllbnRfaWQiOiJ0ZXN0X2NsaWVudCIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSJ9.aW52YWxpZF9zaWduYXR1cmU"

    # Enable logging capture
    with caplog.at_level(logging.ERROR):
        result = validator.validate_token(token)

    # Ensure that the token validation logged an "Invalid token signature" message
    assert "Invalid token signature" in caplog.text

    # Ensure that validate_token returns None for an invalid signature
    assert result is None

    # Ensure that mock_construct is called (signature verification was attempted)
    mock_construct.assert_called_once()

# Verify that the validate_token method handles a JWT token with invalid claims


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
@patch('cognito_token_validator.validator.jwt.get_unverified_header')
@patch('cognito_token_validator.validator.jwt.get_unverified_claims')  # Correct method for extracting claims
@patch('cognito_token_validator.validator.jwk.construct')  # Correctly mock the JWK signature verification
def test_token_validator_invalid_claims_logs_error(mock_construct, mock_get_unverified_claims, mock_get_unverified_header, mock_fetch_jwks, caplog):
    # Mock JWKS fetching and token header decoding
    mock_fetch_jwks.return_value = mock_jwks

    # Correctly mock the return value of get_unverified_header
    mock_get_unverified_header.return_value = {
        "kid": "mock_kid",  # This must match the 'kid' in JWKS
        "alg": "RS256"      # Algorithm used to sign the token
    }

    # Mock the unverified claims (JWT payload)
    # Set an invalid 'aud' (client_id)
    mock_get_unverified_claims.return_value = {
        "aud": "invalid_client",  # This should cause a client_id mismatch
        "sub": "user123",
        "email": "user@example.com"
    }

    # Mock the construct method (JWK verification process) to return a valid key
    mock_key = MagicMock()
    mock_key.verify.return_value = True  # Simulate passing verification
    mock_construct.return_value = mock_key

    # Initialize the TokenValidator
    validator = TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",  # The expected valid client_id
        get_auth_header=lambda: "Bearer test_token"
    )

    # Use a valid Base64URL-encoded and padded mock JWT token
    token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1vY2tfa2lkIn0.eyJjbGllbnRfaWQiOiJ0ZXN0X2NsaWVudCIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSJ9.c2lnbmF0dXJl"

    # Enable logging capture
    with caplog.at_level(logging.ERROR):
        result = validator.validate_token(token)

    # Ensure that the token validation logged a client_id mismatch error
    assert "Invalid client_id" in caplog.text

    # Ensure that validate_token returns None for a client_id mismatch
    assert result is None

    # Ensure that mock_construct is called (signature verification was attempted)
    mock_construct.assert_called_once()


@patch('cognito_token_validator.validator.time.time', return_value=1700000000)  # Mock current time closer to current
def test_validate_token_cached_valid_token(mock_time):
    # Initialize the TokenValidator
    validator = TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",
        get_auth_header=lambda: "Bearer test_token"
    )

    # Set up a cached valid token (exp in the future)
    token = "valid_cached_token"
    validator.token_cache[token] = {
        "aud": "test_client",
        "sub": "user123",
        "email": "user@example.com",
        "exp": 1700001000  # Expiration in the future
    }

    # Call validate_token, expecting the cached token to be returned
    result = validator.validate_token(token)

    # Check that the cached token is returned
    assert result["aud"] == "test_client"
    assert result["email"] == "user@example.com"


@patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')  # Mock JWKS fetching
@patch('cognito_token_validator.validator.time.time', return_value=1700000000)  # Mock current time
def test_validate_token_expired_cached_token(mock_time, mock_fetch_jwks, caplog):
    # Initialize the TokenValidator
    validator = TokenValidator(
        region="us-east-1",
        user_pool_id="test_pool",
        client_id="test_client",
        get_auth_header=lambda: "Bearer test_token"
    )

    # Set up a cached expired token (exp in the past)
    token = "expired_cached_token"
    validator.token_cache[token] = {
        "aud": "test_client",
        "sub": "user123",
        "email": "user@example.com",
        "exp": 1600000000  # Expiration in the past
    }

    # Call validate_token, expecting the cached token to be removed and None to be returned
    with caplog.at_level(logging.INFO):
        result = validator.validate_token(token)

    # Ensure that the expired token is removed from the cache
    assert token not in validator.token_cache

    # Ensure that None is returned
    assert result is None

    # Ensure that a log message "Token is expired" is written
    assert "Token is expired" in caplog.text

    # Ensure JWKS fetching is not triggered
    mock_fetch_jwks.assert_not_called()
