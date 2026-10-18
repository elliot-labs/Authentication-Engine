import type { NextFunction, Request, Response } from 'express';
import { assertGuardEquals, type tags } from 'typia';
import { AuthenticationEngine } from '../Authentication.js';
import type { Uuid } from '../utility/types/constant/typia.js';

/** Instance of the authentication engine used for validating tokens. */
const authEngine = AuthenticationEngine.getInstance();

/**
 * Configures and creates a new instance of an authentication middleware for Express.js.
 * This middleware validates incoming requests based on the provided tenant and audience lists.
 * It checks for the presence and format of the Authorization header and verifies the access token.
 * If the authentication fails, it responds with a 401 status and passes an error to the next middleware.
 * If the authentication succeeds, it passes control to the next middleware in the stack.
 * @param tenantList List of tenant UUIDs that are allowed to access the resource.
 * @param audienceList List of audience UUIDs that are allowed to access the resource.
 * @returns An Express middleware function that validates the authentication of incoming requests.
 */
export function newAuthenticationMiddleware(tenantList: Uuid[], audienceList: Uuid[] & tags.MinItems<1>): (request: Request, response: Response, next: NextFunction) => Promise<void> {
    // #region Input Validation
    assertGuardEquals(tenantList);

    assertGuardEquals(audienceList);
    // #endregion Input Validation

    /**
     * Middleware function to cryptographically validate authentication.
     * @param request The incoming request object.
     * @param response The outgoing response object.
     * @param next Function that triggers the next middleware in the stack.
     */
    return async function confirmAuthN(request: Request, response: Response, next: NextFunction): Promise<void> {
        /** Authorization header extracted from the request, to be validated. */
        const authorizationHeader = request.get('Authorization');

        // Check if the authorization header is not present
        if (typeof authorizationHeader !== 'string') {
            // Indicate the end user is not authenticated
            response.status(401);

            // Send the incorrect state context info to the error handling middleware
            next(new TypeError('Missing authorization header!', { 'cause': 'Input validation!' }));

            // Stop execution to prevent fallthrough
            return;
        }

        // Check if the authorization header is a Bearer token
        if (!authorizationHeader.toLowerCase().startsWith('bearer ')) {
            // Indicate the end user is not authenticated
            response.status(401);

            // Send the incorrect state context info to the error handling middleware
            next(new TypeError('Invalid authorization header format!', { 'cause': 'Input validation!' }));

            // Stop execution to prevent fallthrough
            return;
        }

        /** Bearer token split on the space character. */
        const splitBearer = authorizationHeader.split(' ');

        // Check if the authorization header is a Bearer token with a valid format
        if (splitBearer.length !== 2) {
            // Indicate the end user is not authenticated
            response.status(401);

            // Send the incorrect state context info to the error handling middleware
            next(new TypeError('Invalid authorization header format!', { 'cause': 'Input validation!' }));

            // Stop execution to prevent fallthrough
            return;
        }

        // Check if the access token is valid using the authentication engine.
        if (!await authEngine.confirmAccessToken(splitBearer[1]!, audienceList, tenantList)) {
            // Indicate the end user is not authenticated
            response.status(401);

            // Send the incorrect state context info to the error handling middleware
            next(new TypeError('Invalid access token!', { 'cause': 'Authentication failed!' }));

            // Stop execution to prevent fallthrough
            return;
        }

        // Authentication was successful, pass the execution to the next middleware in the stack
        next();
    };
}
