/** Extracted Authorization metadata sourced from the JWT in the authorization header. */
type AuthorizationData = import('../utility/types/Authentication.js').AuthorizationData;

declare module 'express-serve-static-core' {
    /** The request object represents the HTTP request and has properties for the request query string, parameters, body, HTTP headers, and other request metadata. */
    interface Request {
        /** Extracted Authorization metadata sourced from the JWT in the authorization header. */
        'bearerAuthorizationData'?: AuthorizationData;
    }
}
