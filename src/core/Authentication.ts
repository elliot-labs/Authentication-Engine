/* eslint-disable no-continue */
import type { AccessTokenV1Claims, AccessTokenV2Claims, AuthorizationData, JwksKeySet, OpenIdConfiguration } from '../utility/types/core/Authentication.js';
import { assertGuard, assertGuardEquals, is, type tags } from 'typia';
import { decode, verify } from 'jws';
import { DefaultAzureCredential } from '@azure/identity';
import { NULL_UUID } from '../utility/constants/core.js';
import type { Uuid } from '../utility/types/constant/typia.js';

/** Engine responsible for managing and validating authentication with Entra ID. */
export class AuthenticationEngine {
    /** Instance of the AuthenticationEngine singleton. */
    static #instance: AuthenticationEngine | undefined = void 0;
    /** Configured authentication credential that logs into Entra ID and can be used to retrieve access tokens. */
    public entra: DefaultAzureCredential;
    /** Instance of the settings engine to use for authentication configuration. */

    // #region Initialization

    /** Initializes the properties and state of the AuthenticationEngine. */
    private constructor() {
        // Configure the initial auth credential
        this.entra = new DefaultAzureCredential({ 'requiredEnvVars': ['AZURE_TOKEN_CREDENTIALS'] });
    }

    /**
     * Retrieves the singleton instance of the AuthenticationEngine.
     * If the instance does not exist, it creates a new one.
     * @returns The singleton instance of the AuthenticationEngine.
     */
    public static getInstance(): AuthenticationEngine {
        // Check if the singleton instance already exists. If not, create it.
        if (AuthenticationEngine.#instance === void 0) {
            // Instantiate the class instance
            AuthenticationEngine.#instance = new AuthenticationEngine();
        }

        // Return the singleton instance of the AuthenticationEngine.
        return AuthenticationEngine.#instance;
    }

    /**
     * Resets the singleton instance to an uninitialized state.
     * @deprecated This is used for testing purposes to ensure that each test can start with a clean slate.
     */
    public static clearInstance(): void { this.#instance = void 0; }

    // #endregion Initialization

    /**
     * Validates that a JWT is a Microsoft Entra access token issued for one of the permitted application and tenant combinations.
     *
     * This method performs authentication validation only. A return value of `true` means the token was structurally valid, Microsoft-signed, within its validity window, issued by an accepted tenant, and targeted at one of the supplied client IDs.
     *
     * It does not determine what the caller is allowed to do. Authorization must be evaluated separately, typically by calling `getAccessTokenAuthzData()` only after this method returns `true`.
     *
     * Validation flow:
     * 1. Validates the function inputs and safely decodes the JWT.
     * 2. Rejects malformed tokens, tokens without a `kid`, and tokens that do not match the expected Microsoft Entra access-token claim shape.
     * 3. Rejects tokens containing a `nonce` so ID tokens are not accidentally accepted as access tokens.
     * 4. Extracts the issuing tenant ID from the token's `iss` claim.
     * 5. Determines the tenants against which the token will be validated:
     * - When `tenantIdList` contains one or more tenant IDs, the token must have been issued by one of those tenants.
     * - When `tenantIdList` is empty, the method operates in explicit multi-tenant mode and validates against the tenant identified by the token's issuer.
     * 6. Retrieves each candidate tenant's OpenID configuration from Microsoft, using the token's `ver` claim to select the v1.0 or v2.0 metadata endpoint.
     * 7. Requires the token's `iss` claim to exactly match the Microsoft-provided issuer for a candidate tenant.
     * 8. For each supplied client ID, retrieves the tenant's signing keys from the metadata JWKS endpoint, scoped through the `appid` query parameter.
     * 9. Selects the signing key whose `kid` matches the JWT header and verifies the `RS256` signature using the Microsoft-provided certificate.
     * 10. Requires at least one permitted tenant and client ID combination to successfully validate the token's issuer and signature.
     * 11. Validates the time-based claims (`nbf` and `exp`), requires the audience claim (`aud`) to match one of the supplied client IDs, and enforces the configured tenant restriction.
     *
     * This method is intentionally fail-closed. Input validation failures, parsing errors, metadata retrieval failures, signing-key mismatches, signature verification failures, and claim mismatches result in `false` rather than being exposed to the caller as exceptions.
     *
     * Security notes and misuse risks:
     * - Do not treat a `true` result as authorization. A valid token may still lack the required application roles, delegated scopes, or directory roles.
     * - Do not pass an empty `tenantIdList` unless the application intentionally supports multi-tenant authentication. An empty list allows validation against the tenant identified by the token's Microsoft Entra issuer.
     * - Populate `clientIdList` only with application IDs for protected resources this application trusts. Every additional client ID broadens the set of audiences accepted by this method.
     * - Populate `tenantIdList` only with tenant IDs the application trusts. Every additional tenant ID broadens the set of issuers accepted by this method.
     * - Do not use this method for ID tokens. ID tokens have different validation requirements and are intentionally rejected here.
     * - Do not make security decisions using claims extracted from a non-validated token. Validate the token first, and then extract authorization data.
     * - Metadata and signing-key retrieval depend on Microsoft services. Transient network or service failures return `false`; callers must not bypass validation in response to those failures.
     * @param accessToken JWT access token to validate.
     * @param clientIdList Application IDs of the APIs or application resources that may appear in the token's `aud` claim. The token must target at least one client ID in this list.
     * @param tenantIdList Tenant IDs permitted to issue the token. The token must be issued by one tenant in this list. Pass an empty array to explicitly enable multi-tenant validation using the tenant identified by the token's `iss` claim.
     * @returns `true` when the token passes all structural, issuer, signature, time, audience, and tenant checks; otherwise, `false`.
     * @example
     * const authEngine = await AuthenticationEngine.getInstance();
     * const isValid = await authEngine.confirmAccessToken(bearerToken, [settings.clientId], [settings.tenantId]);
     *
     * if (!isValid) { throw new Error('Access token validation failed.'); }
     *
     * const authz = authEngine.getAccessTokenAuthzData(bearerToken);
     * if (!authz.permissionList.includes('CheckIn.Read')) { throw new Error('Authenticated token is missing the required permission.'); }
     * @example
     * const authEngine = await AuthenticationEngine.getInstance();
     * const isValid = await authEngine.confirmAccessToken(bearerToken, [settings.primaryClientId, settings.secondaryClientId], [settings.productionTenantId, settings.partnerTenantId]);
     *
     * if (!isValid) { throw new Error('Access token validation failed.'); }
     * @example
     * const authEngine = await AuthenticationEngine.getInstance();
     *
     * // Explicit multi-tenant validation: accept the issuer tenant for any permitted application.
     * const isValid = await authEngine.confirmAccessToken(bearerToken, [settings.clientId], []);
     *
     * if (!isValid) { return false; }
     *
     * const authz = authEngine.getAccessTokenAuthzData(bearerToken);
     * console.log(`Authenticated subject ${ authz.subjectId } from tenant ${ authz.tenantId }`);
     */
    public async confirmAccessToken(accessToken: string, clientIdList: Uuid[], tenantIdList: Uuid[]): Promise<boolean> {
        // #region Input Validation

        // If any input validation fails, return false instead of throwing
        try {
            assertGuardEquals(accessToken);

            assertGuardEquals(clientIdList);

            assertGuardEquals(tenantIdList);
        } catch (_error) { return false; }

        /** Parsed components of the access token used for validation. */
        let tokenComponents: ReturnType<typeof decode> = null;

        // Safely decode the token and return false if fails on syntax error
        try { tokenComponents = decode(accessToken); } catch (_error) { return false; }

        // If the token is not in the correct format, it is not valid
        if (tokenComponents === null) { return false; }

        // If the token header doesn't contain a key ID, it is not valid as we cannot determine which signing key to use to validate the signature
        if (!tokenComponents.header.kid) { return false; }

        // If the required claims are not present in the token, it is not valid
        if (!is<AccessTokenV1Claims | AccessTokenV2Claims>(tokenComponents.payload)) { return false; }

        // Prevent ID tokens from being validated by accident
        if (tokenComponents.payload.nonce) { return false; }
        // #endregion Input Validation

        // #region Cryptographic Validation

        /** This is the tenant ID as provided by the access token's 'iss' claim. */
        const tokenTenantId = this.#findTenantIdFromIssuer(tokenComponents.payload.iss);

        // If no tenant could be extracted, it is not a valid MSFT token
        if (!tokenTenantId) { return false; }

        /** Tenant ID to be used for validation. If the NULL UUID is provided, the tenant ID from the access token will be used. */
        const computedTenantIdList = tenantIdList.length === 0 ? [tokenTenantId] : tenantIdList;

        /** Flag that indicates whether the tenant has been successfully validated. */
        let tenantValidated = false;

        // Iterate through each tenant and ensure that the token is valid for at least one of them
        for (const requestedTenant of computedTenantIdList) {
            /**
             * OpenID configuration for the tenant ID specified in the access token.
             * If a tenant ID is provided to in the function parameters, uses that one instead and ignores the token's tenant ID.
             * This value can be trusted as it is from Microsoft.
             */
            let openIdConfig: OpenIdConfiguration | undefined;

            // Gracefully attempt config retrieval
            try { openIdConfig = await this.#getTenantConfig(requestedTenant, tokenComponents.payload.ver === '2.0' ? '2.0' : '1.0'); } catch (_error) { continue; }

            // If the OpenID configuration cannot be retrieved for the tenant specified in the token, it is not valid as we cannot validate the issuer or retrieve signing keys to validate the signature
            if (!openIdConfig) { return false; }

            // If the Microsoft provided issuer doesn't match the token provided issuer, the token is not valid
            if (tokenComponents.payload.iss !== openIdConfig.issuer) { continue; }

            // Iterate through each client ID to validate the token against the signing keys for that client.
            for (const clientId of clientIdList) {
                /** Signing keys that MSFT has specified are valid for access tokens issued to this tenant's app. */
                let signingKeyList: JwksKeySet;

                // Gracefully attempt signing key retrieval
                try { signingKeyList = await this.#getTenantSigningKeys(openIdConfig, clientId); } catch (_error) { continue; }

                /** Key ID that matches the token header's key ID. Undefined if no matching key is found. */
                const selectedKey = signingKeyList.keys.find((publicKey) => publicKey.kid === tokenComponents.header.kid);

                // If no key can be found that matches the key ID in the token header, the token is not valid as we cannot verify the signature without the correct key
                if (!selectedKey) { return false; }

                /** PEM-encoded certificate for the selected key which will be used to verify the token's signature. */
                const pemEncodedCertificate = `-----BEGIN CERTIFICATE-----\n${ selectedKey.x5c[0] }\n-----END CERTIFICATE-----`;

                // If the signature cryptographically verifies successfully, then it is a Microsoft signed access token
                try { if (verify(accessToken, 'RS256', pemEncodedCertificate)) { tenantValidated = true; } } catch (_error) { continue; }
            }
        }

        // If the tenant was not validated, return false to indicate the token is not validated
        if (!tenantValidated) { return false; }

        // #endregion Cryptographic Validation

        // #region Claims Validation

        /** Current date and time for validating token claims. */
        const now = new Date();

        /** Timestamp indicating that times after this are valid. */
        const notBefore = new Date(tokenComponents.payload.nbf * 1000);

        /** Timestamp indicating that times before this are valid. */
        const expiresAt = new Date(tokenComponents.payload.exp * 1000);

        // If the current time is before the notBefore claim, the token is not valid yet and therefore not valid
        if (now < notBefore) { return false; }

        // If the current time is after the expiresAt claim, the token is no longer valid
        if (now > expiresAt) { return false; }

        // If the client ID from the token's audience claim doesn't match the client ID configured for validation, then the token is not valid for this app
        if (!clientIdList.includes(tokenComponents.payload.aud)) { return false; }

        // If not in "all mode" and the provided tenant ID doesn't match the allowed list, the token is not valid for the expected tenant(s).
        if (tenantIdList.length !== 0 && !tenantIdList.includes(tokenTenantId)) { return false; }

        // #endregion Claims Validation

        // If all checks pass, return true
        return true;
    }

    /**
     * Extracts and processes the authorization data from the provided access token.
     * @param accessToken Access token to extract the claims from.
     * @returns Processed authorization data for easy consumption within the app.
     */
    public getAccessTokenAuthzData(accessToken: string): AuthorizationData {
        // #region Input Validation
        assertGuardEquals(accessToken);
        // #endregion Input Validation

        /** Current state of the AuthZ data that has been extracted from the access token. */
        const authzData: AuthorizationData = {
            'entraRoleList': [],
            'objectId': null,
            'permissionList': [],
            'subjectId': '',
            'tenantId': NULL_UUID
        };

        /** Raw claims from the access token to be processed and extracted. */
        const tokenClaims = decode(accessToken);

        // Ensure that the token is in the correct format before continuing
        if (tokenClaims === null) { throw new TypeError('The provided access token is not a valid JWT!', { 'cause': 'Input validation!' }); }

        // Ensure that the token contains the expected claims before continuing, as the rest of the function relies on those claims being present and in the correct format
        if (!is<AccessTokenV1Claims | AccessTokenV2Claims>(tokenClaims.payload)) { throw new TypeError('The provided access token does not contain the expected claims!', { 'cause': 'Input validation!' }); }

        /** Extracted tenant ID from the issuer claim in the access token. */
        const tenantId = this.#findTenantIdFromIssuer(tokenClaims.payload.iss);

        // If the tenant ID cannot be extracted from the token configured issuer, throw an error as it is not valid
        if (!tenantId) { throw new TypeError('The provided access token does not contain a valid tenant ID in the issuer claim!', { 'cause': 'Input validation!' }); }

        // Populate the list of Microsoft Entra roles assigned to the authenticated principal if the 'wids' claim is present
        if (tokenClaims.payload.wids) { authzData.entraRoleList = tokenClaims.payload.wids; }

        // Populate the Object ID of the authenticated principal if the claim is present in the token
        if (tokenClaims.payload.oid) { authzData.objectId = tokenClaims.payload.oid; }

        // If application permissions are present, process them
        if (tokenClaims.payload.roles) {
            // Iterate through each provided Application permission assigned to the authenticated principal
            for (const permission of tokenClaims.payload.roles) {
                // Add the current permission to the list of permissions in the authz data if it is not already present
                if (!authzData.permissionList.includes(permission)) { authzData.permissionList.push(permission); }
            }
        }

        // If delegated permissions are present, process them
        if (tokenClaims.payload.scp) {
            // Iterate through each provided Delegated permission assigned to the authenticated principal
            for (const permission of tokenClaims.payload.scp.split(' ')) {
                // Add the current permission to the list of permissions in the authz data if it is not already present
                if (!authzData.permissionList.includes(permission)) { authzData.permissionList.push(permission); }
            }
        }

        // Populate the subject ID of the authenticated principal
        authzData.subjectId = tokenClaims.payload.sub;

        // Populate the tenant ID that the authenticated principal authenticated to
        authzData.tenantId = tenantId;

        // Return the extracted and computed data to the caller
        return authzData;
    }

    /**
     * Looks up the Microsoft Entra tenant ID for a given domain.
     * @param domain Domain used in resolving the tenant ID.
     * @returns GUID of the tenant, if no tenant found, undefined.
     */
    public async findTenantId(domain: string & tags.Format<'hostname'>): Promise<string & tags.Format<'uuid'> | undefined> {
        // #region Input Validation
        assertGuardEquals(domain);
        // #endregion Input Validation

        /** OpenID configuration for the specified domain. If it exists. */
        const config = await this.#getTenantConfig(domain, '2.0');

        // Check if the config could be found, if not then return undefined as the tenant ID cannot be found without the config
        if (!config) { return void 0; }

        // Return the tenant ID extracted from the issuer claim in the OpenID configuration, if it cannot be extracted then return undefined as it is not valid
        return this.#findTenantIdFromIssuer(config.issuer);
    }

    /*
     * Helper Functions
     */
    // #region Helper Functions

    /**
     * Extracts the tenant ID from the issuer URL.
     * Supports untrusted issuer strings as long as they are in the correct format, but will return undefined for any issuer that is not a valid URL or does not have a valid tenant ID in the expected segment of the path.
     * @param issuer Issuer URL from which to extract the tenant ID.
     * @returns Tenant ID if available and valid, otherwise undefined.
     */
    // eslint-disable-next-line @typescript-eslint/class-methods-use-this
    #findTenantIdFromIssuer(issuer: string): string & tags.Format<'uuid'> | undefined {
        // #region Input Validation
        assertGuardEquals(issuer);
        // #endregion Input Validation

        // If the token configured issuer is not a valid URL, return undefined as it is not valid
        if (!URL.canParse(issuer)) { return void 0; }

        /** Issuer broken down into components so that regex is not needed when operating on the values within. */
        const parsedIssuerUrl = new URL(issuer);

        /** Extracted tenant ID from the token configured issuer URL. */
        // eslint-disable-next-line @typescript-eslint/prefer-destructuring
        const tenantId = parsedIssuerUrl.pathname.split('/')[1];

        // If the tenant ID extracted from the token configured issuer is not a valid UUID, return undefined as it is not valid
        if (!is<string & tags.Format<'uuid'>>(tenantId)) { return void 0; }

        // Return the tenant ID
        return tenantId;
    }

    /**
     * Retrieves the OpenID configuration for a specified tenant and version.
     * @param tenantIdentifier Tenant ID or domain for which to retrieve the OpenID configuration.
     * @param version Schema version of the OpenID configuration to retrieve ('1.0' or '2.0').
     * @returns OpenID configuration if available, otherwise undefined.
     */
    // eslint-disable-next-line @typescript-eslint/class-methods-use-this
    async #getTenantConfig(tenantIdentifier: string & tags.Format<'uuid'> | string & tags.Format<'hostname'>, version: '1.0' | '2.0'): Promise<OpenIdConfiguration | undefined> {
        // #region Input Validation
        assertGuardEquals(tenantIdentifier);

        assertGuardEquals(version);
        // #endregion Input Validation

        /** Raw OpenID configuration response for the specified tenant and version. */
        const rawConfigResponse = await fetch(`https://login.microsoftonline.com/${ tenantIdentifier }/${ version === '2.0' ? 'v2.0/' : '' }.well-known/openid-configuration`);

        // If the config is not available, return undefined as it is an invalid tenant
        if (rawConfigResponse.status !== 200) { return void 0; }

        /** Parsed OpenID configuration for the specified tenant and version. */
        const parsedOpenIdConfig = await rawConfigResponse.json() as OpenIdConfiguration;

        // Ensure that the parsed config is in the correct format before trusting its contents
        if (!is(parsedOpenIdConfig)) { return void 0; }

        // Return the parsed OpenID configuration for the specified tenant and version
        return parsedOpenIdConfig;
    }

    /**
     * Retrieves the signing keys for a specified tenant and OpenID configuration.
     * @param openIdConfig OpenID configuration for the specified tenant.
     * @param clientId Client ID for which to retrieve the specific/custom signing keys for.
     * @returns Signing keys for the specified tenant and OpenID configuration if available, otherwise no signing keys will be returned.
     */
    // eslint-disable-next-line @typescript-eslint/class-methods-use-this
    async #getTenantSigningKeys(openIdConfig: OpenIdConfiguration, clientId: string & tags.Format<'uuid'>): Promise<JwksKeySet> {
        // #region Input Validation
        assertGuard(openIdConfig);

        assertGuardEquals(clientId);
        // #endregion Input Validation

        /** Parsed URL for the keyset request. */
        const keyRequestUrl = new URL(openIdConfig.jwks_uri);

        // Update the AppID query parameter so that the keyset specific to the app is used for signature validation
        keyRequestUrl.searchParams.set('appid', clientId);

        /** Raw response for the keyset request. */
        const keysetResponse = await fetch(keyRequestUrl);

        if (keysetResponse.status !== 200) { return { 'keys': [] }; }

        /** Keyset from Microsoft for the specified tenant and app used to sign all the access tokens. */
        const parsedKeyset = await keysetResponse.json() as JwksKeySet;

        // Ensure that the minimum set of properties are present on the keyset response before trusting its contents and using it for token validation.
        if (!is(parsedKeyset)) { return { 'keys': [] }; }

        // Iterate through each key and add the issuer if not present
        for (const signingKey of parsedKeyset.keys) {
            // Check if the issuer is not present on the signing key and add it if not present
            if (!('issuer' in signingKey)) { signingKey.issuer = openIdConfig.issuer; }
        }

        // Return the parsed keyset to the caller
        return parsedKeyset;
    }

    // #endregion Helper Functions
}
