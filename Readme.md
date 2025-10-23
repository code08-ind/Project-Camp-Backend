# Start From 02:19 Mins.

# JWT Token
Here we read about the JWT tokens: JWT Token Comprises of the following parts:
1. Header
2. Payload
3. Signature

## Header
The header typically consists of two parts: the type of the token, which is JWT, and the signing algorithm being used, such as HMAC SHA256 or RSA.

## Payload
The payload contains the claims. Claims are statements about an entity (typically, the user) and additional data. There are three types of claims: registered, public, and private claims.

## Signature
To create the signature part you have to take the encoded header, the encoded payload, a secret, and the algorithm specified in the header. This is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.

## Types of JWT Tokens
1. Access Token
2. Refresh Token

### Access Token
An access token is a short-lived token that is used to access protected resources. It is usually valid for a short period of time, such as 15 minutes to an hour. Once the access token expires, the user needs to obtain a new one using a refresh token. It also has a data within it that contains information about the user and their permissions.

### Refresh Token
A refresh token is a long-lived token that is used to obtain a new access token when the current access token expires. Refresh tokens are typically valid for a longer period of time, such as days or weeks. They are used to maintain user sessions without requiring the user to re-authenticate frequently. Refresh tokens are usually stored securely on the client side and are sent to the server when a new access token is needed.

On the server side, we create both the Access and Refresh tokens when the user logs in. The access token is sent to the client and is used to authenticate subsequent requests to protected resources. The refresh token is also sent to the client and is stored securely, typically in an HTTP-only cookie or local storage. Access tokens are stateless.

When the access token expires, the error code is sent back to the client and the client can send the refresh token to a specific endpoint on the server to obtain a new access token. The server verifies the refresh token, and if it is valid, generates a new access token and sends it back to the client. This process allows for seamless user experiences without requiring frequent logins.