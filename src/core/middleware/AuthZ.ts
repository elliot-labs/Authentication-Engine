import type { NextFunction, Request, Response } from 'express';
import { AuthenticationEngine } from '../Authentication.js';
import { NULL_UUID } from '../../utility/constants/core.js';

/** Instance of the authentication engine used for validating tokens. */
const authEngine = AuthenticationEngine.getInstance();

/**
 * Middleware function to extract authorization data from the request.
 * Information that is extracted from the Bearer token in the Authorization header is attached to the request object as a new property for use in subsequent middleware and route handlers.
 * @param request The incoming HTTP request.
 * @param response The outgoing HTTP response.
 * @param next The next middleware function in the stack.
 */
export function extractAuthZ(request: Request, response: Response, next: NextFunction): void {
    /** Authorization header extracted from the request, to be validated. */
    const authorizationHeader = request.get('Authorization');

    // If in debug mode and no token is provided, use a dummy AuthZ payload to allow for development and testing without needing a valid access token
    if (!authorizationHeader) {
        /*
         * Set dummy data on the request for development and testing purposes when in debug mode.
         *
         * Value reference:
         * Entra role list is hard coded to Global Admin.
         * Object ID is dummy value.
         * Permissions list is hard coded to all permissions.
         * Subject ID is a dummy value.
         * Tenant ID is always the null UUID.
         */
        request.bearerAuthorizationData = {
            'entraRoleList': ['62e90394-69f5-4237-9190-012177145e10'],
            'objectId': '926f4018-ecb5-4f87-966e-0e76704d1791',
            'permissionList': ['Everything.ReadWrite.All'],
            'subjectId': 't1jE7aqxPF4k1nEBnmpHC5zaJpQpbz',
            'tenantId': NULL_UUID
        };

        // Pass execution to the next middleware in the stack
        next();

        // Stop execution to prevent fallthrough
        return;
    }

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

    // Extract the AuthZ data and make it available to all subsequent routes and middleware
    request.bearerAuthorizationData = authEngine.getAccessTokenAuthzData(splitBearer[1]!);

    // AuthZ extraction complete, pass the execution to the next middleware in the stack
    next();
}
