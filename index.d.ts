/** Extracted Authorization metadata sourced from the JWT in the authorization header. */
type AuthorizationData = import('./src/utility/types/core/Authentication.js').AuthorizationData;

declare namespace Express {
    /** The request object represents the HTTP request and has properties for the request query string, parameters, body, HTTP headers, and so on. */
    export interface Request {
        /** Extracted Authorization metadata sourced from the JWT in the authorization header. */
        'bearerAuthorizationData': AuthorizationData;
    }
}
