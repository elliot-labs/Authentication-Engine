import type { tags } from 'typia';

/**
 * Represents the authorization data for a user.
 *
 * This object does not represent that the token has been validated.
 * It is only an extraction of the claims.
 */
export interface AuthorizationData {
    /** List of Microsoft Entra role template IDs for each Entra role assigned to the principal. */
    'entraRoleList': (string & tags.Format<'uuid'>)[];
    /** Object ID of the principal. */
    'objectId': string & tags.Format<'uuid'> | null;
    /** List of delegated and application permissions granted to the principal. */
    'permissionList': string[];
    /**
     * Subject ID of the principal.
     * Opaque string that uniquely identifies the principal within the enterprise app that the end user is authenticating to.
     * If the principal is updated, this values remains the same.
     * Similar to objectId, but while objectId is the same across all apps in the tenant, subjectId is different per app. This means that if the same user authenticates to two different apps, the objectId claim will be the same in both tokens, but the subjectId claim will be different.
     */
    'subjectId': string;
    /** Tenant ID of the tenant the principal authenticated from. */
    'tenantId': string & tags.Format<'uuid'>;
}

/** Minimal set of OpenID Connect configuration properties used for token validation. */
export interface OpenIdConfiguration {
    /** URL of the endpoint that contains all of the public keys used to verify tokens for the specific tenant. */
    'jwks_uri': string;
    /** Identifier of the issuer of the tokens for the specific tenant. */
    'issuer': string;
}

/** Represents a (public) JSON Web Key (JWK) used for validating access token signatures. */
interface JwksKey {
    /** Key type, e.g., RSA. */
    'kty': string;
    /** Intended use of the key, e.g., sig for signature. */
    'use': string;
    /** Unique identifier for the key. */
    'kid': string;
    /** X.509 certificate thumbprint. */
    'x5t': string;
    /** Modulus value for the RSA key. */
    'n': string;
    /** Exponent value for the RSA key. */
    'e': string;
    /** X.509 certificate chain. */
    'x5c': string[];
    /**
     * Name of the sovereign cloud instance (azure commercial, gov cloud, dod) this key belongs to.
     * @example microsoftonline.com
     * @example microsoftonline.us
     */
    'cloud_instance_name': string;
    /** Issuer value for the key. Only present on v2.0 schema. */
    'issuer'?: string;
}

/** Keyset allowed for signing access tokens for the specified tenant. */
export interface JwksKeySet {
    /** List of JSON Web Key (JWK) objects used for token validation. */
    'keys': JwksKey[];
}

/** Minimal set of claims used for both v1.0 and v2.0 Microsoft access tokens. */
interface AccessTokenCommonClaims {
    /** Audience for which the token is intended, which app is this token allowed to be used with. */
    'aud': string;
    /** Timestamp of when the token expires. Token is not valid if used after this time stamp. */
    'exp': number;
    /** List of object IDs of the groups the user is a member of, inclusion of the values is configured on the app's auth config. */
    'groups'?: (string & tags.Format<'uuid'>)[];
    /** Timestamp of when the token was issued. */
    'iat': number;
    /** Issuer of the access token. */
    'iss': string;
    /** Timestamp of when the token becomes valid. Token is not valid if used before this time stamp. */
    'nbf': number;
    /** Value used by ID tokens to prevent replay attacks. Indicates the token is an ID token. */
    'nonce'?: string;
    /** Object ID of the principal that authenticated. */
    'oid'?: string & tags.Format<'uuid'>;
    /** Roles assigned to the access token's principal. */
    'roles'?: string[];
    /** Space separated list of permissions granted to the access token's principal. */
    'scp'?: string;
    /**
     * The principal associated with the token.
     * For example, the user of an application.
     * This value is immutable, don't reassign or reuse.
     * The subject is a pairwise identifier that's unique to a particular application ID.
     * If a single user signs into two different applications using two different client IDs, those applications receive two different values for the subject claim.
     * Using the two different values depends on architecture and privacy requirements.
     * See also the oid claim, which does remain the same across applications within a tenant.
     */
    'sub': string;
    /** Denotes the tenant-wide roles assigned to this user, from the section of roles present in Microsoft Entra built-in roles. */
    'wids'?: (string & tags.Format<'uuid'>)[];
}

/** Minimal set of claims used for Microsoft v1.0 access tokens. */
export type AccessTokenV1Claims = AccessTokenCommonClaims & {
    /** User principal name of the authenticated principal. */
    'upn'?: string;
    /** First name of the authenticated principal. */
    'given_name'?: string;
    /** Last name of the authenticated principal. */
    'family_name'?: string;
    /** Schema version of the Microsoft access token. */
    'ver': '1.0';
};

/** Minimal set of claims used for Microsoft v2.0 access tokens. */
export type AccessTokenV2Claims = AccessTokenCommonClaims & {
    /** The primary username that represents the user. The value could be an email address, phone number, or a generic username without a specified format. Use the value for username hints and in human-readable UI as a username. */
    'preferred_username'?: string;
    /** Schema version of the Microsoft access token. */
    'ver': '2.0';
};
