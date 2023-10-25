# webIdentityCredentialProcess

A process that allows to perform credential vending based out of token files.
Credentials are returned in AWS Credential process format on stdout.
All logging of the credential process goes to stderr.

Mandatory environment variables:
```sh
export AWS_DEFAULT_REGION="eu-west-1"
export AWS_ROLE_ARN="..."
export AWS_WEB_IDENTITY_TOKEN_FILE="/path/to/your/token"
```

Optional environment variables:
```sh
export AWS_ASSUME_WEB_IDENTITY_TIMEOUT=5  # For controlling how long to await assumeRoleWithWebIdentityApiCall (expressed in seconds defaults to 5)
export AWS_WEB_IDENTITY_CREDENTIAL_PROCESS_CACHE_FILE="/path/to/file/where/you/want/to/cache/credentials"
export AWS_WEB_IDENTITY_DURATION=3600
export AWS_WEB_IDENTITY_PROVIDER_ID="..." # For providers that reqiure specifying that (see AWS docs on assumeRoleWithWebIdentity)
export AWS_WEB_IDENTITY_SESSION_NAME="..."
export AWS_WEB_IDENTITY_CREDENTIAL_PROCESS_LOG_LEVEL="DEBUG
```



# Common issues

## operation error STS: AssumeRoleWithWebIdentity, https response error StatusCode: 400, RequestID: f4570356-caf6-45a0-9033-bd1bbca3c63b, InvalidIdentityToken: Provided Token is not a Login With Amazon token

The token file either doesn't contain a valid token or the token is followed by a newline character.

# Dev notes

## Build binary
go build -o build/webidentity_credential_process creds.go


## Do a test run
This requires that you have a 'login with amazon'-token

```sh
export AWS_ROLE_ARN="arn:aws:iam::01234568910:role/test-role-login-with-amazon"
export AWS_WEB_IDENTITY_TOKEN_FILE="/tmp/token"
export AWS_DEFAULT_REGION="eu-west-1"
export WEB_IDENTITY_PROVIDER_ID="www.amazon.com"

echo -n "<token>" > /tmp/token
go run creds.go
```