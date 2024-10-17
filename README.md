# Token Validator

A Python package for validating AWS Cognito tokens and using them as decorators.
You can use this package with Flask or any other Python framework.

## Installation

```bash
pip install cognito-token-validator
```
# Usage
### Initialization
First, initialize the TokenValidator with the necessary parameters:

* region: The AWS region where your Cognito user pool is located.
* user_pool_id: The ID of your Cognito user pool.
* client_id: The client ID of your Cognito application.
* get_auth_header: A function that retrieves the token from the request context.
* whitelisted_emails (optional): A List of string containing the whitelist of emails. if the list is empty, all emails are allowed. If the list is not empty, only the emails in the list are allowed.
* cache_max_size (optional): The maximum number of tokens to cache. Default is 10.
* ttl (optional): The time-to-live for cached tokens in seconds. Default is 3600.
        

```python
from cognito_token_validator import TokenValidator

# Initialize the TokenValidator
token_validator = TokenValidator(
    region='us-east-1',
    user_pool_id='your_user_pool_id',
    client_id='your_client_id',
    get_auth_header=lambda: request.headers.get('Authorization'),
    whitelisted_emails=['example@example.com']
)
```

### Using with Flask
To use the TokenValidator in a Flask app, apply the token_required decorator to your routes:

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/protected')
@token_validator.token_required
def protected():
    return 'This is a protected route'

if __name__ == '__main__':
    app.run(debug=True)
```

# License
This project is licensed under the MIT License - see the LICENSE file for details.
