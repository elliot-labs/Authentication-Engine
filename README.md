# Authentication Engine

[![NPM Version](https://img.shields.io/npm/v/%40elliot-labs%2Fauthentication-engine?style=flat-square)](https://www.npmjs.com/package/@elliot-labs/authentication-engine) [![NPM License](https://img.shields.io/npm/l/%40elliot-labs%2Fauthentication-engine?style=flat-square)](https://github.com/elliot-labs/Authentication-Engine/blob/main/LICENSE)

Microsoft Entra ID authentication and authorization utilities for TypeScript services and Express APIs.

`@elliot-labs/authentication-engine` provides both sides of service authentication:

- **Inbound authentication** validates Microsoft Entra access tokens presented to the consuming service.
- **Outbound authentication** provides a configured `DefaultAzureCredential` that the consuming service can use to authenticate as its Microsoft Entra service principal, workload identity, managed identity, or supported developer identity when calling downstream services.
- **Authorization extraction** normalizes application roles, delegated scopes, Microsoft Entra directory roles, and principal identifiers for use by application authorization policies.

The package also includes Express middleware for protecting APIs and resolving Microsoft Entra tenant IDs from verified domains.

## Features

- Provides inbound authentication for Express APIs
- Provides outbound service authentication through `DefaultAzureCredential`
- Validates Microsoft Entra ID v1.0 and v2.0 access tokens
- Verifies `RS256` signatures using Microsoft-published signing certificates
- Validates token issuer, audience, tenant, `nbf`, and `exp` claims
- Supports explicit single-tenant and multi-tenant configurations
- Rejects ID tokens containing a `nonce`
- Extracts application roles, delegated scopes, Entra directory roles, and principal identifiers
- Resolves Microsoft Entra tenant IDs from verified domains
- Uses Typia for runtime validation
- Fails closed when token validation or Microsoft metadata retrieval fails

> **Important:** Authentication Engine validates Microsoft Entra access tokens. It does not validate ID tokens.

## Installation

```bash
npm install @elliot-labs/authentication-engine
```

## Requirements

- Latest Node LTS release
- TypeScript
- ECMAScript module mode
- Express 5.3.0 or later when using the middleware exports
- A Microsoft Entra app registration, enterprise application, or managed identity as required by the implementation

This package is published as an ECMAScript module.

## Quick Start

```TypeScript
import express from 'express';
import { extractAuthZ, newAuthenticationMiddleware } from '@elliot-labs/authentication-engine';

const app = express();
const tenantId = '11111111-1111-1111-1111-111111111111';
const clientId = '22222222-2222-2222-2222-222222222222';

app.use(newAuthenticationMiddleware([tenantId], [clientId]));
app.use(extractAuthZ);

app.get('/profile', (request, response) => {
    response.json(request.bearerAuthorizationData);
});

app.listen(3000);
```

Middleware order is security-sensitive:

1. `newAuthenticationMiddleware()` validates the access token.
2. `extractAuthZ` extracts authorization claims from the validated token.
3. Authorization middleware or route handlers evaluate the extracted permissions.

> **Security:** `extractAuthZ` decodes and extracts claims but does not cryptographically validate the token. Never trust extracted authorization data unless `newAuthenticationMiddleware()` or `AuthenticationEngine.confirmAccessToken()` has already validated the token.

## Exports

```TypeScript
import { AuthenticationEngine, extractAuthZ, newAuthenticationMiddleware } from '@elliot-labs/authentication-engine';
```

| Export                        | Description                                                                                                                                   |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `AuthenticationEngine`        | Singleton engine for access-token validation, authorization-data extraction, outbound service authentication, and tenant discovery.           |
| `newAuthenticationMiddleware` | Creates Express middleware that validates bearer access tokens.                                                                               |
| `extractAuthZ`                | Optionally extracts normalized authorization data from a bearer token and attaches it to the Express request. It does not validate the token. |

## Express Authentication

Create authentication middleware by supplying the trusted tenant IDs and API application IDs.

```TypeScript
import express from 'express';
import { newAuthenticationMiddleware } from '@elliot-labs/authentication-engine';

const app = express();
const authentication = newAuthenticationMiddleware(['11111111-1111-1111-1111-111111111111'], ['22222222-2222-2222-2222-222222222222']);

app.use('/api', authentication);

app.get('/api/status', (_request, response) => {
    response.json({ 'authenticated': true });
});
```

The middleware:

- Requires an `Authorization` header
- Requires the `Bearer <token>` format
- Validates the Microsoft signature
- Validates the token issuer
- Validates the tenant
- Validates the audience
- Validates the token validity window
- Sets the response status to `401` and passes an error to the Express error pipeline when authentication fails

### Multiple Audiences and Tenants

The middleware accepts a token when it is valid for at least one configured tenant and one configured audience.

```TypeScript
const authentication = newAuthenticationMiddleware(['11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333333'], ['22222222-2222-2222-2222-222222222222', '44444444-4444-4444-4444-444444444444']);

app.use('/api', authentication);
```

Every tenant or audience added to these lists expands the set of access tokens trusted by the application. Only configure tenants and application IDs that the API intentionally trusts.

### Explicit Multi-Tenant Authentication

Pass an empty tenant list to validate the token against the Microsoft Entra tenant identified by its issuer.

```TypeScript
const multiTenantAuthentication = newAuthenticationMiddleware([], ['22222222-2222-2222-2222-222222222222']);

app.use('/api', multiTenantAuthentication);
```

> **Caution:** An empty tenant list intentionally enables multi-tenant authentication. The token must still target one of the configured audiences, but it may originate from any Microsoft Entra tenant that can obtain a token for that audience. Do not use an empty tenant list when the API should trust only a defined set of tenants.

## Extracting Authorization Data

Use `extractAuthZ` to extract normalized authorization data from a bearer access token and attach it to `request.bearerAuthorizationData`.

The middleware combines relevant Microsoft Entra access-token claims into an authorization object that is easier for subsequent middleware and route handlers to consume.

| Property         | Description                                                                                    |
| ---------------- | ---------------------------------------------------------------------------------------------- |
| `entraRoleList`  | Microsoft Entra directory-role template IDs from the token's `wids` claim.                     |
| `objectId`       | Object ID from the token's `oid` claim, or `null` when unavailable.                            |
| `permissionList` | Deduplicated application roles and delegated scopes from the token's `roles` and `scp` claims. |
| `subjectId`      | Subject identifier from the token's `sub` claim.                                               |
| `tenantId`       | Microsoft Entra tenant ID extracted from the token issuer.                                     |

Application permissions from `roles` and delegated permissions from `scp` are combined into `permissionList`.

### Protected Routes

For protected routes, authenticate the token before extracting and using its authorization claims.

```TypeScript
import express from 'express';
import { extractAuthZ, newAuthenticationMiddleware } from '@elliot-labs/authentication-engine';

const app = express();
const tenantId = '11111111-1111-1111-1111-111111111111';
const clientId = '22222222-2222-2222-2222-222222222222';

app.get('/api/profile', newAuthenticationMiddleware([tenantId], [clientId]), extractAuthZ, (request, response) => {
    const authorization = request.bearerAuthorizationData;

    if (!authorization) {
        response.status(500).json({ 'error': 'Authorization data was not extracted.' });
        return;
    }

    response.json({ 'subjectId': authorization.subjectId, 'objectId': authorization.objectId, 'tenantId': authorization.tenantId, 'permissions': authorization.permissionList, 'entraRoles': authorization.entraRoleList });
});
```

For protected routes, use this middleware order:

1. `newAuthenticationMiddleware()` validates the token.
2. `extractAuthZ` extracts normalized claims from the validated token.
3. Authorization middleware evaluates the required roles or permissions.
4. The route handler performs the requested operation.

### Optional Authentication

`extractAuthZ` can also be used without authentication middleware when a route supports optional authentication.

If the request does not contain a usable bearer authorization header, the middleware continues without setting `request.bearerAuthorizationData`.

```TypeScript
app.get('/api/catalog', extractAuthZ, (request, response) => {
    const authorization = request.bearerAuthorizationData;
    response.json({ 'authenticated': authorization !== undefined, 'subjectId': authorization?.subjectId, 'tenantId': authorization?.tenantId, 'results': [] });
});
```

> **Security:** On its own, `extractAuthZ` does not establish that a token or its claims are trustworthy. Do not grant access, return protected data, or perform privileged operations based only on data extracted by this middleware.

### Header Behavior

`extractAuthZ` processes the authorization header only when the header uses the `Bearer` scheme and contains exactly two space-delimited components.

When the header is missing, uses another scheme, has no token value, or contains more than two space-delimited components, `request.bearerAuthorizationData` remains `undefined` and the request continues.

A value with the `Bearer <token>` shape is passed to `AuthenticationEngine.getAccessTokenAuthzData()`. The method throws when the value is not a decodable JWT, lacks the expected Microsoft Entra access-token claims, or has an issuer from which a tenant ID cannot be extracted. Register an Express error handler after routes using this middleware.

### TypeScript Request Extension

Importing `extractAuthZ` loads the package's Express request extension, allowing TypeScript to recognize `request.bearerAuthorizationData`.

Because extraction is optional, implementations must account for the property being `undefined`.

```TypeScript
const authorization = request.bearerAuthorizationData;

if (!authorization) {
    response.status(401).json({ 'error': 'Authorization data is unavailable.' });
    return;
}
```

## Enforcing Permissions

Authentication proves that a request contains a valid token. It does not prove that the caller is permitted to perform a particular operation.

```TypeScript
import type { NextFunction, Request, Response } from 'express';

function requirePermission(permission: string) {
    return function authorize(request: Request, response: Response, next: NextFunction): void {
        const authorization = request.bearerAuthorizationData;

        if (!authorization) {
            response.status(401);
            next(new TypeError('Authorization data is unavailable.', { 'cause': 'Authentication required!' }));
            return;
        }

        if (!authorization.permissionList.includes(permission)) {
            response.status(403);
            next(new TypeError(`Missing required permission: ${permission}`, { 'cause': 'Authorization failed!' }));
            return;
        }

        next();
    };
}
```

Apply authorization after authentication and extraction.

```TypeScript
app.get('/api/check-ins', newAuthenticationMiddleware([tenantId], [clientId]), extractAuthZ, requirePermission('CheckIn.Read'), (request, response) => {
    response.json({ 'subjectId': request.bearerAuthorizationData?.subjectId, 'checkIns': [] });
});
```

Use `401 Unauthorized` when authentication is missing or invalid. Use `403 Forbidden` when authentication succeeds but the authenticated principal lacks the required authorization.

## Direct Token Validation

The authentication engine can be used without Express.

```TypeScript
import { AuthenticationEngine } from '@elliot-labs/authentication-engine';

const authenticationEngine = AuthenticationEngine.getInstance();
const token = process.env.ACCESS_TOKEN;

if (!token) { throw new Error('ACCESS_TOKEN is required.'); }

const isValid = await authenticationEngine.confirmAccessToken(token, ['22222222-2222-2222-2222-222222222222'], ['11111111-1111-1111-1111-111111111111']);

if (!isValid) { throw new Error('Access-token validation failed.'); }

const authorization = authenticationEngine.getAccessTokenAuthzData(token);

if (!authorization.permissionList.includes('CheckIn.Read')) { throw new Error('The authenticated principal does not have CheckIn.Read.'); }

console.log({ 'subjectId': authorization.subjectId, 'tenantId': authorization.tenantId });
```

### Multiple Trusted Resources

```TypeScript
const isValid = await authenticationEngine.confirmAccessToken(token, ['22222222-2222-2222-2222-222222222222', '44444444-4444-4444-4444-444444444444'], ['11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333333']);
```

### Direct Multi-Tenant Validation

```TypeScript
const isValid = await authenticationEngine.confirmAccessToken(token, ['22222222-2222-2222-2222-222222222222'], []);
```

An empty tenant list directs the engine to validate against the tenant identified by the token's Microsoft Entra issuer.

## Tenant Discovery

Resolve a Microsoft Entra tenant ID from a verified domain.

```TypeScript
import { AuthenticationEngine } from '@elliot-labs/authentication-engine';

const authenticationEngine = AuthenticationEngine.getInstance();
const tenantId = await authenticationEngine.findTenantId('example.com');

if (!tenantId) { throw new Error('No Microsoft Entra tenant could be resolved for example.com.'); }

console.log(tenantId);
```

`findTenantId()` retrieves the domain's Microsoft OpenID configuration and extracts the tenant UUID from the returned issuer. The method returns `undefined` when a usable configuration or tenant ID cannot be found.

## API

### `AuthenticationEngine.getInstance()`

Returns the singleton authentication engine.

```TypeScript
const authenticationEngine = AuthenticationEngine.getInstance();
```

### `AuthenticationEngine.confirmAccessToken()`

```TypeScript
confirmAccessToken(accessToken: string, clientIdList: Uuid[], tenantIdList: Uuid[]): Promise<boolean>
```

Validates a Microsoft Entra access token.

- `accessToken`: Encoded JWT access token.
- `clientIdList`: One or more trusted API application IDs. The token's `aud` claim must match an entry.
- `tenantIdList`: Trusted tenant IDs. Pass an empty array only when multi-tenant authentication is intentional.

The method returns `true` when the token passes structural, issuer, signature, validity-window, audience, and tenant validation. It intentionally returns `false` for input-validation failures, malformed tokens, unexpected claims, unavailable metadata, missing signing keys, invalid signatures, invalid validity windows, invalid audiences, and invalid tenants.

### `AuthenticationEngine.getAccessTokenAuthzData()`

```TypeScript
getAccessTokenAuthzData(accessToken: string): AuthorizationData
```

Decodes a token and returns normalized authorization data. This method does not verify the token signature. Call it only after successful authentication when the returned data will be trusted.

The method throws when the token is malformed, has an unexpected claim shape, or has an issuer from which a tenant ID cannot be extracted.

### `AuthenticationEngine.findTenantId()`

```TypeScript
findTenantId(domain: string): Promise<string | undefined>
```

Resolves a Microsoft Entra tenant UUID from a hostname.

### `AuthenticationEngine.entra`

A shared `DefaultAzureCredential` instance used to authenticate the service consuming this package.

This supports outbound service authentication:

- `confirmAccessToken()` authenticates callers sending requests to the service.
- `entra` authenticates the consuming service when it accesses downstream APIs or Azure resources.

The identity used by `entra` depends on the credential selected through `DefaultAzureCredential`. This package requires `AZURE_TOKEN_CREDENTIALS` so the consuming service explicitly controls the selected credential type.

```bash
export AZURE_TOKEN_CREDENTIALS=ManagedIdentityCredential
```

For supported credentials, required environment variables, credential-chain behavior, and deployment-specific configuration, refer to Microsoft's maintained documentation:

- [Azure Identity client library for JavaScript](https://learn.microsoft.com/en-us/javascript/api/overview/azure/identity-readme)
- [DefaultAzureCredential API reference](https://learn.microsoft.com/en-us/javascript/api/@azure/identity/defaultazurecredential)
- [Credential chains in the Azure Identity library for JavaScript](https://learn.microsoft.com/en-us/azure/developer/javascript/sdk/authentication/credential-chains)

#### Requesting a Token

Use `entra.getToken()` to request an application-context access token for a downstream resource.

```TypeScript
import { AuthenticationEngine } from '@elliot-labs/authentication-engine';

const authenticationEngine = AuthenticationEngine.getInstance();
const accessToken = await authenticationEngine.entra.getToken('api://33333333-3333-3333-3333-333333333333/.default');

if (!accessToken) { throw new Error('The service could not obtain an access token.'); }

const response = await fetch('https://downstream.example.com/api/resources', { 'headers': { 'Authorization': `Bearer ${accessToken.token}` } });
```

The identity represented by the credential must be granted the permissions required by the downstream resource. Successfully obtaining an access token does not by itself guarantee that the downstream operation is authorized.

> **Important:** `entra` provides application-context authentication for the consuming service. It does not exchange or forward the inbound caller's identity and does not implement the Microsoft identity platform On-Behalf-Of flow.

## Inbound and Outbound Authentication

Authentication Engine supports two independent authentication boundaries:

1. **Inbound authentication** validates access tokens presented to the consuming service.
2. **Outbound authentication** provides a `DefaultAzureCredential` that the consuming service can use to authenticate to downstream resources.

Caller permissions and service permissions remain separate. A caller authorized to invoke the consuming service does not automatically inherit the consuming service's permissions to downstream resources.

## Express Error Handling

Authentication failures are sent to the Express error pipeline after the response status is set to `401`. Register an error-handling middleware after the protected routes.

```TypeScript
import type { ErrorRequestHandler } from 'express';

const errorHandler: ErrorRequestHandler = (error, _request, response, _next) => {
    const statusCode = response.statusCode >= 400 ? response.statusCode : 500;
    response.status(statusCode).json({ 'error': statusCode === 401 ? 'Unauthorized' : statusCode === 403 ? 'Forbidden' : 'Internal Server Error', 'message': error instanceof Error ? error.message : 'An unexpected error occurred.' });
};

app.use(errorHandler);
```

Avoid returning token contents, signing-key details, or internal validation information to callers in production.

## Security Model

The validation flow:

1. Validates method inputs.
2. Safely decodes the JWT.
3. Requires a signing-key identifier in the JWT header.
4. Validates the expected Microsoft Entra access-token claim shape.
5. Rejects tokens containing a `nonce`.
6. Extracts the tenant ID from the issuer.
7. Retrieves tenant-specific Microsoft OpenID metadata.
8. Requires an exact issuer match.
9. Retrieves signing keys for each configured application ID.
10. Selects the certificate matching the token's `kid`.
11. Verifies the `RS256` signature.
12. Validates the `nbf` and `exp` claims.
13. Validates the `aud` claim against the trusted application IDs.
14. Enforces the configured tenant restrictions.

Validation is intentionally fail-closed. If metadata or signing keys cannot be retrieved, the token is not accepted.

## Security Guidance

### Authenticate Before Authorizing

Correct:

```TypeScript
app.use(authentication);
app.use(extractAuthZ);
app.use(requirePermission('CheckIn.Read'));
```

Incorrect:

```TypeScript
app.use(extractAuthZ);
app.use(requirePermission('CheckIn.Read'));
```

### Restrict Trusted Audiences

Only include application IDs belonging to protected resources the application trusts. Every additional client ID expands the set of audiences the package can accept.

### Restrict Trusted Tenants

Prefer an explicit tenant allowlist unless the application is intentionally multi-tenant.

### Treat Network Failures as Authentication Failures

Token validation depends on Microsoft OpenID metadata and signing-key endpoints. Applications must not bypass authentication when those endpoints are unavailable.

### Use HTTPS

Bearer tokens grant access to protected resources. Only accept bearer tokens over HTTPS and never write complete access tokens to application logs.

### Evaluate Permissions Per Operation

A valid access token may still lack the application role or delegated scope required by a route. Validate the exact permission required for each sensitive operation.

## Missing Authorization Data

`extractAuthZ` does not create placeholder authorization data when an authorization header is missing.

When no usable bearer header is present:

- `request.bearerAuthorizationData` remains `undefined`.
- The middleware does not set a response status.
- The middleware does not create an error.
- The request continues to the next middleware or route handler.

This behavior supports optional authentication without granting synthetic permissions or creating a production authorization bypass. Protected routes must continue to use `newAuthenticationMiddleware()` before `extractAuthZ`.

## Testing

The singleton can be reset for isolated tests.

```TypeScript
AuthenticationEngine.clearInstance();
```

`clearInstance()` is deprecated for production use and exists only to provide clean singleton state between tests.

## Service-to-Service Example

The following route validates an inbound caller, verifies the caller's permission, and authenticates the service to a downstream API.

```TypeScript
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { AuthenticationEngine, extractAuthZ, newAuthenticationMiddleware } from '@elliot-labs/authentication-engine';

const app = express();
const authenticationEngine = AuthenticationEngine.getInstance();
const authenticateCaller = newAuthenticationMiddleware(['11111111-1111-1111-1111-111111111111'], ['22222222-2222-2222-2222-222222222222']);

function requirePermission(permission: string) {
    return function authorizeCaller(request: Request, response: Response, next: NextFunction): void {
        const authorization = request.bearerAuthorizationData;

        if (!authorization) {
            response.status(401);
            next(new TypeError('Authorization data is unavailable.', { 'cause': 'Authentication required!' }));
            return;
        }

        if (!authorization.permissionList.includes(permission)) {
            response.status(403);
            next(new TypeError(`Missing required permission: ${permission}`, { 'cause': 'Authorization failed!' }));
            return;
        }

        next();
    };
}

app.get('/api/reports', authenticateCaller, extractAuthZ, requirePermission('Reports.Read'), async (_request, response, next) => {
    try {
        const downstreamToken = await authenticationEngine.entra.getToken('api://33333333-3333-3333-3333-333333333333/.default');
        if (!downstreamToken) { throw new Error('Downstream service authentication failed.'); }
        const downstreamResponse = await fetch('https://reports.example.com/api/reports', { 'headers': { 'Authorization': `Bearer ${downstreamToken.token}` } });
        if (!downstreamResponse.ok) { throw new Error(`The reports service returned ${downstreamResponse.status}.`); }
        response.json(await downstreamResponse.json());
    } catch (error) {
        next(error);
    }
});
```

This example creates two independent trust boundaries:

- The inbound caller must present a valid token for the current service and possess `Reports.Read`.
- The current service must obtain its own token for the downstream reports API, and its identity must have the downstream API's application permission.

## Support

- Repository: <https://github.com/elliot-labs/Authentication-Engine>
- Issues: <https://github.com/elliot-labs/Authentication-Engine/issues>
- Package: <https://www.npmjs.com/package/@elliot-labs/authentication-engine>
- Homepage: <https://elliot-labs.com>

## License

Authentication Engine is available under the [MIT License](https://github.com/elliot-labs/Authentication-Engine/blob/main/LICENSE).
