package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	time "time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/aws-sdk-go/aws/awserr"
)

type CredentialResponse struct {
	Version         int8
	AccessKeyId     *string
	SecretAccessKey *string
	SessionToken    *string
	Expiration      *time.Time
}

func NewCredentialResponse(cred types.Credentials) (response *CredentialResponse) {
	response = new(CredentialResponse)
	response.Version = 1
	response.AccessKeyId = cred.AccessKeyId
	response.SecretAccessKey = cred.SecretAccessKey
	response.SessionToken = cred.SessionToken
	response.Expiration = cred.Expiration
	return response
}

// OS environment variables
const AWS_DEFAULT_REGION = "AWS_DEFAULT_REGION"
const AWS_ROLE_ARN = "AWS_ROLE_ARN"
const AWS_WEB_IDENTITY_CREDENTIAL_PROCESS_CACHE_FILE = "AWS_WEB_IDENTITY_CREDENTIAL_PROCESS_CACHE_FILE"
const AWS_WEB_IDENTITY_DURATION = "AWS_WEB_IDENTITY_DURATION"
const AWS_WEB_IDENTITY_PROVIDER_ID = "AWS_WEB_IDENTITY_PROVIDER_ID"
const AWS_WEB_IDENTITY_SESSION_NAME = "AWS_WEB_IDENTITY_SESSION_NAME"
const AWS_WEB_IDENTITY_TOKEN_FILE = "AWS_WEB_IDENTITY_TOKEN_FILE"

func getWebIdentityDuration() (duration *int32) {
	webIdentityDuration, hasWebIdentityDuration := os.LookupEnv(AWS_WEB_IDENTITY_DURATION)
	if !hasWebIdentityDuration {
		// Default to 3600
		return aws.Int32(3600)
	}

	i64, err := strconv.ParseInt(webIdentityDuration, 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid value for %s %s", AWS_WEB_IDENTITY_DURATION, webIdentityDuration)
	}
	return aws.Int32(int32(i64))
}

func getWebIdentitySessionName() (sessionName *string) {
	awsWebIdenitySessionName, hasAwsWebIdenitySessionName := os.LookupEnv(AWS_WEB_IDENTITY_SESSION_NAME)
	if !hasAwsWebIdenitySessionName {
		return aws.String("webIdenityCredentialProcess")
	}
	return aws.String(awsWebIdenitySessionName)
}

func getWebIdentityRoleArn() (role_arn *string) {
	awsRoleArn, hasAwsRoleArn := os.LookupEnv(AWS_ROLE_ARN)
	if !hasAwsRoleArn {
		failWithMessage(fmt.Sprintf("%s is a mandatory OS environment variable.", AWS_ROLE_ARN))
	}
	return aws.String(awsRoleArn)
}

func getAwsDefaultRegion() (default_region string) {
	awsDefaultRegion, hasAwsDefaultRegion := os.LookupEnv(AWS_DEFAULT_REGION)
	if !hasAwsDefaultRegion {
		failWithMessage(fmt.Sprintf("%s is a mandatory OS environment variable.", AWS_DEFAULT_REGION))
	}
	return awsDefaultRegion

}

func failWithMessage(msg string) {
	fmt.Fprintf(os.Stderr, "%s\n", msg)
	os.Exit(1)
}

func getWebIdentityToken() (token *string) {
	awsWebIdentityTokenFile, hasAwsWebIdentityTokenFile := os.LookupEnv(AWS_WEB_IDENTITY_TOKEN_FILE)
	if !hasAwsWebIdentityTokenFile {
		failWithMessage(fmt.Sprintf("%s is a mandatory OS environment variable.", AWS_WEB_IDENTITY_TOKEN_FILE))
	}
	awsWebIdentityTokenFileHandle, err := os.Open(awsWebIdentityTokenFile)
	if err != nil {
		failWithMessage(fmt.Sprintf("%s must point to an existing file.", AWS_WEB_IDENTITY_TOKEN_FILE))
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer awsWebIdentityTokenFileHandle.Close()
	byteValue, _ := io.ReadAll(awsWebIdentityTokenFileHandle)
	return aws.String(string(byteValue))
}

func getCredentialsUsingWebIdentityToken() (response *CredentialResponse, err error) {
	svc := sts.New(sts.Options{Region: string(getAwsDefaultRegion())})
	var input *sts.AssumeRoleWithWebIdentityInput
	input = &sts.AssumeRoleWithWebIdentityInput{
		DurationSeconds:  getWebIdentityDuration(),
		RoleArn:          getWebIdentityRoleArn(),
		WebIdentityToken: getWebIdentityToken(),
		RoleSessionName:  getWebIdentitySessionName(),
	}
	web_idenity_provider_id, has_web_identity_provider_id := os.LookupEnv(AWS_WEB_IDENTITY_PROVIDER_ID)
	if has_web_identity_provider_id {
		input.ProviderId = aws.String(web_idenity_provider_id)
	}
	ctx, _ := context.WithTimeout(context.TODO(), 5*1000*1000*1000)
	result, err := svc.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				failWithMessage(aerr.Error())
			}
		} else {
			failWithMessage(err.Error())
		}
		return nil, err
	}
	return NewCredentialResponse(*result.Credentials), nil
}

func getAwsDir() (awsDir string, err error) {
	dirname, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get home dir %s.\n", err)
		return "", err
	}
	awsDir = fmt.Sprintf("%s/%s", dirname, ".aws")
	err = os.Mkdir(awsDir, 0700)
	return awsDir, nil
}

func getCredsFilename() (filename string) {
	webIdentityCredentialProcessCacheFile, haswebIdentityCredentialProcessCacheFile := os.LookupEnv(AWS_WEB_IDENTITY_CREDENTIAL_PROCESS_CACHE_FILE)
	if !haswebIdentityCredentialProcessCacheFile {
		dirname, err := getAwsDir()
		if err != nil {
			failWithMessage(fmt.Sprintf("Could not get home dir %s and %s not provided.\n", err, AWS_WEB_IDENTITY_CREDENTIAL_PROCESS_CACHE_FILE))
		}
		return fmt.Sprintf("%s/%s", dirname, ".webIdentityCredentialProcess.json")
	}
	return webIdentityCredentialProcessCacheFile
}

func storeCredentialResponse(marshaledResponse []byte) (err error) {
	return os.WriteFile(getCredsFilename(), marshaledResponse, 0600)
}

func getCredentialResponse() (response *CredentialResponse, err error) {
	// First try to read from file but on any exception use api
	jsonFile, err := os.Open(getCredsFilename())
	if err != nil {
		return getCredentialsUsingWebIdentityToken()
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	byteValue, _ := io.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &response)
	if err != nil {
		// If we cannot get the cached value get other value
		return getCredentialsUsingWebIdentityToken()
	}
	// Check expiry
	remaining_seconds := -time.Now().Sub(*response.Expiration).Seconds()
	if remaining_seconds-600 < 0 {
		// If we are too close to expire
		fmt.Fprintf(os.Stderr, "Remaining seconds to expiry %f is too small, will get new credentials.\n", remaining_seconds)
		return getCredentialsUsingWebIdentityToken()
	}
	return response, nil
}

func main() {
	// Inspired by https://github.com/aws/aws-sdk-go/blob/main/service/sts/examples_test.go
	creds, err := getCredentialResponse()
	if err != nil {
		failWithMessage(fmt.Sprintf("Could not get credentials: %s\n", err))
	}
	jsonData, err := json.Marshal(creds)
	if err != nil {
		failWithMessage(fmt.Sprintf("Could not marshal json: %s\n", err))
	}
	storeCredentialResponse(jsonData)
	fmt.Printf("%s\n", jsonData)
}
