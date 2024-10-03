import unittest
from unittest.mock import patch, MagicMock

import requests
from cognito_token_validator.validator import TokenValidator
import time
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


class TestTokenValidator(unittest.TestCase):

    @patch('cognito_token_validator.validator.TokenValidator._fetch_jwks')
    def setUp(self, mock_fetch_jwks):
        mock_fetch_jwks.return_value = mock_jwks
        self.region = "us-west-2"
        self.user_pool_id = "us-west-2_123456789"
        self.client_id = "client_id_123"
        self.get_auth_header = MagicMock()
        self.whitelisted_emails = ["test@example.com"]
        self.validator = TokenValidator(
            self.region,
            self.user_pool_id,
            self.client_id,
            self.get_auth_header,
            self.whitelisted_emails
        )

    @patch('requests.get')
    def test_fetch_jwks_failure(self, mock_get):
        mock_get.side_effect = requests.RequestException("Error")

        with self.assertRaises(RuntimeError):
            self.validator._fetch_jwks()

    @patch('jose.jwt.get_unverified_header')
    def test_get_hmac_key(self, mock_get_unverified_header):
        mock_get_unverified_header.return_value = {"kid": "1234"}
        self.validator.jwks = {"keys": [{"kid": "1234", "kty": "RSA"}]}

        key = self.validator._get_hmac_key("token")
        self.assertEqual(key, {"kid": "1234", "kty": "RSA"})

    @patch('jose.jwt.get_unverified_header')
    def test_get_hmac_key_not_found(self, mock_get_unverified_header):
        mock_get_unverified_header.return_value = {"kid": "5678"}
        self.validator.jwks = {"keys": [{"kid": "1234", "kty": "RSA"}]}

        key = self.validator._get_hmac_key("token")
        self.assertIsNone(key)

    @patch('jose.jwt.get_unverified_claims')
    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_validate_token_success(self, mock_get_unverified_header, mock_construct, mock_get_unverified_claims):
        mock_get_unverified_header.return_value = {"kid": "1234"}
        mock_construct.return_value.verify.return_value = True
        mock_get_unverified_claims.return_value = {
            "aud": self.client_id,
            "email": "test@example.com",
            "exp": time.time() + 3600
        }
        self.validator.jwks = {"keys": [{"kid": "1234", "kty": "RSA"}]}

        token = "header.payload.signature"
        decoded_token = self.validator.validate_token(token)
        self.assertIsNotNone(decoded_token)

    @patch('jose.jwt.get_unverified_claims')
    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_validate_token_expired(self, mock_get_unverified_header, mock_construct, mock_get_unverified_claims):
        mock_get_unverified_header.return_value = {"kid": "1234"}
        mock_construct.return_value.verify.return_value = True
        mock_get_unverified_claims.return_value = {
            "aud": self.client_id,
            "email": "test@example.com",
            "exp": time.time() - 3600
        }
        self.validator.jwks = {"keys": [{"kid": "1234", "kty": "RSA"}]}

        token = "header.payload.signature"
        decoded_token = self.validator.validate_token(token)
        self.assertIsNone(decoded_token)

    @patch('jose.jwt.get_unverified_claims')
    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_validate_token_invalid_signature(self, mock_get_unverified_header, mock_construct, mock_get_unverified_claims):
        mock_get_unverified_header.return_value = {"kid": "1234"}
        mock_construct.return_value.verify.return_value = False
        self.validator.jwks = {"keys": [{"kid": "1234", "kty": "RSA"}]}

        token = "header.payload.signature"
        decoded_token = self.validator.validate_token(token)
        self.assertIsNone(decoded_token)

    @patch('jose.jwt.get_unverified_claims')
    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_validate_token_invalid_audience(self, mock_get_unverified_header, mock_construct, mock_get_unverified_claims):
        mock_get_unverified_header.return_value = {"kid": "1234"}
        mock_construct.return_value.verify.return_value = True
        mock_get_unverified_claims.return_value = {
            "aud": "invalid_audience",
            "email": "test@example.com",
            "exp": time.time() + 3600
        }
        self.validator.jwks = {"keys": [{"kid": "1234", "kty": "RSA"}]}

        token = "header.payload.signature"
        decoded_token = self.validator.validate_token(token)
        self.assertIsNone(decoded_token)

    @patch('jose.jwt.get_unverified_claims')
    @patch('jose.jwk.construct')
    @patch('jose.jwt.get_unverified_header')
    def test_validate_token_email_not_whitelisted(self, mock_get_unverified_header, mock_construct, mock_get_unverified_claims):
        mock_get_unverified_header.return_value = {"kid": "1234"}
        mock_construct.return_value.verify.return_value = True
        mock_get_unverified_claims.return_value = {
            "aud": self.client_id,
            "email": "not_whitelisted@example.com",
            "exp": time.time() + 3600
        }
        self.validator.jwks = {"keys": [{"kid": "1234", "kty": "RSA"}]}

        token = "header.payload.signature"
        decoded_token = self.validator.validate_token(token)
        self.assertIsNone(decoded_token)

    @patch('cognito_token_validator.validator.TokenValidator.validate_token')
    def test_token_required_decorator(self, mock_validate_token):
        mock_validate_token.return_value = {"email": "test@example.com"}

        @self.validator.token_required
        def protected_route(user_info=None):
            return "Success", 200

        self.get_auth_header.return_value = "Bearer valid_token"
        response, status_code = protected_route()
        self.assertEqual(status_code, 200)
        self.assertEqual(response, "Success")

    @patch('cognito_token_validator.validator.TokenValidator.validate_token')
    def test_token_required_decorator_invalid_token(self, mock_validate_token):
        mock_validate_token.return_value = None

        @self.validator.token_required
        def protected_route(user_info=None):
            return "Success", 200

        self.get_auth_header.return_value = "Bearer invalid_token"
        response, status_code = protected_route()
        self.assertEqual(status_code, 403)
        self.assertIn("Token is invalid", response)


if __name__ == '__main__':
    unittest.main()
