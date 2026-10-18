import './expressExtension.js';
import type { NextFunction, Request, Response } from 'express';
import { AuthenticationEngine } from '../Authentication.js';

/** Instance of the authentication engine used for validating tokens. */
const authEngine = AuthenticationEngine.getInstance();

/**
 * Middleware function to extract authorization data from the request.
 * Information that is extracted from the Bearer token in the Authorization header is attached to the request object as a new property for use in subsequent middleware and route handlers.
 * If no valid bearer token is present, the `bearerAuthorizationData` property will remain `undefined`.
 * @param request The incoming HTTP request.
 * @param _response Not used in this middleware.
 * @param next The next middleware function in the stack.
 */
export function extractAuthZ(request: Request, _response: Response, next: NextFunction): void {
    /** Authorization header extracted from the request, to be validated. */
    const authorizationHeader = request.get('Authorization');

    // Check if the authorization header is a Bearer token
    if (typeof authorizationHeader === 'string' && authorizationHeader.toLowerCase().startsWith('bearer ')) {
        /** Bearer token split on the space character. */
        const splitBearer = authorizationHeader.split(' ');

        // Check if the authorization header is a Bearer token with a valid format
        if (splitBearer.length === 2) {
            // Extract the AuthZ data and make it available to all subsequent routes and middleware
            request.bearerAuthorizationData = authEngine.getAccessTokenAuthzData(splitBearer[1]!);
        }
    }

    // AuthZ extraction complete, pass the execution to the next middleware in the stack
    next();
}
