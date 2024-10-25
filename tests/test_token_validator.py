import json
import unittest
from unittest.mock import patch, MagicMock
import time
import requests
from cachetools import TTLCache
from jose import jwt, JWTError
from cognito_token_validator.validator import TokenValidator

# Mock a complete JWKS key
mock_jwks = {
    "keys": [
        {
            "kid": "mock_kid",
            "kty": "RSA",
            "alg": "RS256",
            "n": "mock_modulus",
            "e": "AQAB",
        }
    ]
}

exp_time = time.time() + 3600

# Mock a decoded JWT token with valid claims
mock_token_claims = {"aud": "client_id_123", "email": "test@example.com", "token_use": "id", "exp": exp_time}
mock_token_claims_for_access_token = {
    "client_id": "client_id_123",
    "email": "test@example.com",
    "token_use": "access",
    "exp": exp_time,
}
mock_token_claims_no_aud = {"email": "test@example.com", "token_use": "somethingelse", "exp": exp_time}

# Use a valid Base64URL-encoded and padded mock JWT token
mock_token = jwt.encode(mock_token_claims, "secret", algorithm="HS256")

mock_token_no_aud = jwt.encode(mock_token_claims_no_aud, "secret", algorithm="HS256")

mock_token_with_access_token = jwt.encode(mock_token_claims_for_access_token, "secret", algorithm="HS256")


class TestTokenValidator(unittest.TestCase):

    @patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
    def setUp(self, mock_fetch_jwks):
        mock_fetch_jwks.return_value = mock_jwks
        self.region = "us-west-2"
        self.user_pool_id = "us-west-2_123456789"
        self.client_id = "client_id_123"
        self.get_auth_header = MagicMock()
        self.whitelisted_emails = ["test@example.com"]
        self.validator = TokenValidator(self.region, self.user_pool_id, self.client_id, self.get_auth_header, self.whitelisted_emails)
        self.validator.token_cache = TTLCache(maxsize=10, ttl=3600)

    @patch('requests.get')
    def test_fetch_jwks_success(self, mock_get):
        """Test successful JWKS fetch."""
        mock_response = MagicMock()
        mock_response.json.return_value = mock_jwks
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        jwks = self.validator._fetch_jwks()
        self.assertIn('keys', jwks)

    @patch('requests.get')
    def test_fetch_jwks_failure(self, mock_get):
        """Test failure to fetch JWKS."""
        mock_get.side_effect = requests.RequestException("Failed to fetch JWKS")
        with self.assertRaises(RuntimeError):
            self.validator._fetch_jwks()

    @patch('jose.jwt.get_unverified_header')
    def test_get_hmac_key_success(self, mock_get_header):
        """Test retrieving HMAC key."""
        mock_get_header.return_value = {'kid': 'mock_kid'}
        key = self.validator._get_hmac_key('example_token')
        self.assertIsNotNone(key)
        self.assertEqual(key['kid'], 'mock_kid')

    @patch('jose.jwt.get_unverified_header')
    def test_get_hmac_key_failure(self, mock_get_header):
        """Test failing to retrieve HMAC key."""
        self.validator.jwks = {'keys': [{'kid': 'another_kid'}]}
        mock_get_header.return_value = {'kid': 'mock_kid'}
        key = self.validator._get_hmac_key('mock_kid')
        self.assertIsNone(key)

    @patch('time.time', return_value=1000)
    def test_token_cached_and_valid(self, mock_time):
        """Test token is cached and still valid."""
        cached_token = mock_token_claims.copy()
        cached_token['exp'] = 2000  # Valid until time = 2000
        self.validator.token_cache['example_token'] = cached_token

        result = self.validator.validate_token('example_token')
        self.assertEqual(result, cached_token)

    @patch('time.time', return_value=3000)
    def test_token_cached_but_expired(self, mock_time):
        """Test token is cached but expired."""
        expired_token = mock_token_claims.copy()
        expired_token['exp'] = 2000  # Expired at time = 2000
        self.validator.token_cache['example_token'] = expired_token

        result = self.validator.validate_token('example_token')
        self.assertIsNone(result)
        self.assertNotIn('example_token', self.validator.token_cache)

    @patch('jose.jwt.get_unverified_header')
    def test_no_key_found(self, mock_get_header):
        """Test no key found for the token."""
        mock_get_header.return_value = {'kid': 'unknown_kid'}
        result = self.validator.validate_token(mock_token)
        self.assertIsNone(result)

    def test_token_missing_exp_claim(self):
        """Test token with missing exp claim."""
        claims = mock_token_claims.copy()
        del claims['exp']
        # Mocking the get_unverified_claims to return claims without 'exp'
        with patch('jose.jwt.get_unverified_claims', return_value=claims):
            result = self.validator.validate_token(mock_token)
            self.assertIsNone(result)

    @patch('jose.jwt.get_unverified_header')
    @patch('jose.jwk.construct')
    def test_signature_verification_failed(self, mock_jwk_construct, mock_get_header):
        """Test signature verification fails."""
        mock_get_header.return_value = {'kid': 'mock_kid'}
        mock_jwk = MagicMock()
        mock_jwk.verify.return_value = False
        mock_jwk_construct.return_value = mock_jwk

        result = self.validator.validate_token(mock_token)
        self.assertIsNone(result)

    @patch('jose.jwt.get_unverified_claims')
    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_wrong_audience(self, mock_get_header, mock_jwk_construct, mock_get_claims):
        """Test token issued for the wrong audience."""
        wrong_aud_claims = mock_token_claims.copy()
        wrong_aud_claims['aud'] = 'wrong_client_id'
        mock_get_claims.return_value = wrong_aud_claims
        mock_get_header.return_value = {'kid': 'mock_kid'}
        mock_jwk_construct.return_value = MagicMock()
        mock_jwk_construct.return_value.verify.return_value = True

        result = self.validator.validate_token(mock_token)
        self.assertIsNone(result)

    @patch('jose.jwt.get_unverified_claims')
    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_email_not_whitelisted(self, mock_get_header, mock_jwk_construct, mock_get_claims):
        """Test token email is not in the whitelist."""
        unlisted_email_claims = mock_token_claims.copy()
        unlisted_email_claims['email'] = 'unlisted@example.com'
        mock_get_claims.return_value = unlisted_email_claims
        mock_get_header.return_value = {'kid': 'mock_kid'}
        mock_jwk_construct.return_value = MagicMock()
        mock_jwk_construct.return_value.verify.return_value = True

        result = self.validator.validate_token(mock_token)
        self.assertIsNone(result)

    @patch('jose.jwt.get_unverified_claims')
    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_token_expired(self, mock_get_header, mock_jwk_construct, mock_get_claims):
        """Test token is expired."""
        expired_claims = mock_token_claims.copy()
        expired_claims['exp'] = time.time() - 3600  # Expired 1 hour ago
        mock_get_claims.return_value = expired_claims
        mock_get_header.return_value = {'kid': 'mock_kid'}
        mock_jwk_construct.return_value = MagicMock()
        mock_jwk_construct.return_value.verify.return_value = True

        result = self.validator.validate_token(mock_token)
        self.assertIsNone(result)

    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_token_valid_and_cached(self, mock_get_header, mock_jwk_construct):
        """Test token is valid and should be cached."""
        mock_get_header.return_value = {'kid': 'mock_kid'}
        mock_jwk_construct.return_value = MagicMock()
        mock_jwk_construct.return_value.verify.return_value = True

        result = self.validator.validate_token(mock_token)
        self.assertEqual(result, mock_token_claims)
        self.assertIn(mock_token, self.validator.token_cache)
        self.validator.token_cache.pop(mock_token)

    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_access_token(self, mock_get_header, mock_jwk_construct):
        """Test access token validation."""
        mock_get_header.return_value = {'kid': 'mock_kid'}
        mock_jwk_construct.return_value = MagicMock()
        mock_jwk_construct.return_value.verify.return_value = True

        result = self.validator.validate_token(mock_token_with_access_token)
        self.assertEqual(result, mock_token_claims_for_access_token)

    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_token_no_audience(self, mock_get_header, mock_jwk_construct):
        """Test token has no audience."""
        mock_get_header.return_value = {'kid': 'mock_kid'}
        mock_jwk_construct.return_value = MagicMock()
        mock_jwk_construct.return_value.verify.return_value = True
        result = self.validator.validate_token(mock_token_no_aud)
        self.assertIsNone(result)

    @patch('jose.jwt.get_unverified_header', side_effect=JWTError)
    def test_invalid_token_format(self, mock_get_header):
        """Test invalid token format throws JWTError."""
        result = self.validator.validate_token('invalid_token')
        self.assertIsNone(result)

    def test_token_required_no_auth_header(self):
        """Test case when no authorization header is provided."""
        self.get_auth_header.return_value = None

        @self.validator.token_required
        def mock_route():
            return "Success"

        response_json, status_code = mock_route()
        response = json.loads(response_json)
        self.assertEqual(status_code, 400)
        self.assertEqual(response["message"], "Token not provided or malformed")

    def test_token_required_malformed_auth_header(self):
        """Test case when Bearer token is malformed."""
        self.get_auth_header.return_value = "Invalid token"

        @self.validator.token_required
        def mock_route():
            return "Success"

        response_json, status_code = mock_route()
        response = json.loads(response_json)
        self.assertEqual(status_code, 400)
        self.assertEqual(response["message"], "Token not provided or malformed")

    def test_token_required_missing_token(self):
        """Test case when token is missing after 'Bearer'."""
        self.get_auth_header.return_value = "Bearer "

        @self.validator.token_required
        def mock_route():
            return "Success"

        response_json, status_code = mock_route()
        response = json.loads(response_json)
        self.assertEqual(status_code, 403)
        self.assertEqual(response["message"], "Token is missing!")

    def test_token_required_malformed_token(self):
        """Test case when the token is malformed (not 3 parts)."""
        self.get_auth_header.return_value = "Bearer malformed.token"

        @self.validator.token_required
        def mock_route():
            return "Success"

        response_json, status_code = mock_route()
        response = json.loads(response_json)
        self.assertEqual(status_code, 403)
        self.assertEqual(response["message"], "Token is malformed!")

    @patch('cognito_token_validator.validator.TokenValidator.validate_token')
    def test_token_required_invalid_token(self, mock_validate_token):
        """Test case when the token is invalid."""
        self.get_auth_header.return_value = "Bearer valid.token.structure"
        mock_validate_token.return_value = None

        @self.validator.token_required
        def mock_route():
            return "Success"

        response_json, status_code = mock_route()
        response = json.loads(response_json)
        self.assertEqual(status_code, 403)
        self.assertEqual(response["message"], "Token is invalid!")

    @patch('cognito_token_validator.validator.TokenValidator.validate_token')
    def test_token_required_valid_token(self, mock_validate_token):
        """Test case when the token is valid."""
        self.get_auth_header.return_value = "Bearer valid.token.structure"
        mock_validate_token.return_value = {"user": "test@example.com"}

        @self.validator.token_required
        def mock_route():
            return "Success"

        result = mock_route()
        self.assertEqual(result, "Success")

    @patch('cognito_token_validator.validator.TokenValidator.validate_token')
    def test_token_required_pass_user_info(self, mock_validate_token):
        """Test case when the token is valid and user_info is passed."""
        self.get_auth_header.return_value = "Bearer valid.token.structure"
        mock_validate_token.return_value = {"user": "test@example.com"}

        @self.validator.token_required
        def mock_route(user_info):
            return user_info

        result = mock_route()
        self.assertEqual(result['user'], "test@example.com")

    @patch('cognito_token_validator.validator.TokenValidator.validate_token')
    def test_token_required_token_validation_exception(self, mock_validate_token):
        """Test case when an exception occurs during token validation."""
        self.get_auth_header.return_value = "Bearer valid.token.structure"
        mock_validate_token.side_effect = Exception("Validation failed")

        @self.validator.token_required
        def mock_route():
            return "Success"

        response_json, status_code = mock_route()
        response = json.loads(response_json)
        self.assertEqual(status_code, 500)
        self.assertEqual(response["message"], "Token validation failed!")


if __name__ == "__main__":
    unittest.main()
