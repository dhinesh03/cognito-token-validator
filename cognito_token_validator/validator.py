import requests
import logging
from typing import Callable, Dict, List, Optional
from cachetools import TTLCache
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode
import time

logger = logging.getLogger(__name__)

JWK = Dict[str, str]
JWKS = Dict[str, List[JWK]]


class TokenValidator:
    def __init__(
        self,
        region: str,
        user_pool_id: str,
        client_id: str,
        get_auth_header: Callable[[], Optional[str]],
        whitelisted_emails: List[str] = [],
        cache_max_size: int = 10,
        ttl: int = 3600,
    ):
        self.region = region
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.get_auth_header = get_auth_header
        self.whitelisted_emails = [x.lower() for x in whitelisted_emails]
        self.cognito_issuer = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"
        self.jwks_url = f"{self.cognito_issuer}/.well-known/jwks.json"
        self.jwks = self._fetch_jwks()
        self.token_cache = TTLCache(maxsize=cache_max_size, ttl=ttl)

    def _fetch_jwks(self) -> JWKS:
        try:
            response = requests.get(self.jwks_url)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise RuntimeError("Failed to fetch JWKS")

    def _get_hmac_key(self, token: str) -> Optional[JWK]:
        kid = jwt.get_unverified_header(token).get("kid")
        return next((key for key in self.jwks.get("keys", []) if key.get("kid") == kid), None)

    def validate_token(self, token: str) -> Optional[Dict]:
        if token in self.token_cache:
            decoded_token = self.token_cache[token]
            if time.time() > decoded_token['exp']:
                logger.info('Token is expired')
                del self.token_cache[token]
                return None
            return decoded_token

        try:
            hmac_key = self._get_hmac_key(token)
            if not hmac_key:
                logger.error("No public key found!")
                return None

            hmac_key = jwk.construct(hmac_key)
            message, encoded_signature = token.rsplit(".", 1)
            decoded_signature = base64url_decode(encoded_signature.encode())
            if not hmac_key.verify(message.encode(), decoded_signature):
                logger.error("Signature verification failed!")
                return None

            decoded_token = jwt.get_unverified_claims(token)
            logger.info('Token claims verified', decoded_token)

            if decoded_token['aud'] != self.client_id:
                logger.info('Token was not issued for this audience')
                return None

            if self.whitelisted_emails and decoded_token['email'].lower() not in self.whitelisted_emails:
                logger.info('Token email not in whitelist')
                return None

            if time.time() > decoded_token['exp']:
                logger.info('Token is expired')
                return None

            self.token_cache[token] = decoded_token
            return decoded_token

        except (JWTError, StopIteration):
            logger.error('Token validation failed', exc_info=True)
            return None

    def token_required(self, f):
        def decorator(*args, **kwargs):
            auth_header = self.get_auth_header()
            if not auth_header or not auth_header.startswith('Bearer '):
                return {'status': 'error', 'message': 'Token not provided or malformed'}, 400
            token = auth_header.split()[1]

            if not token:
                return {'message': 'Token is missing!'}, 403
            decoded_token = self.validate_token(token)
            if not decoded_token:
                return {'message': 'Token is invalid!'}, 403
            kwargs['user_info'] = decoded_token
            return f(*args, **kwargs)

        return decorator
