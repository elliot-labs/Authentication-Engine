/** Extracted Authorization metadata sourced from the JWT in the authorization header. */
type AuthorizationData = import('../../utility/types/core/Authentication.js').AuthorizationData;

declare module 'express' {
    /** The request object represents the HTTP request and has properties for the request query string, parameters, body, HTTP headers, and other request metadata. */
    interface Request {
        /** Extracted Authorization metadata sourced from the JWT in the authorization header. */
        'bearerAuthorizationData'?: AuthorizationData;
    }
}
