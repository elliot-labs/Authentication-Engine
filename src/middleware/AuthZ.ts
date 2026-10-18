/* eslint-disable jsdoc/check-indentation */
import './expressExtension.js';
import type { NextFunction, Request, Response } from 'express';
import { AuthenticationEngine } from '../Authentication.js';

/** Instance of the authentication engine used for validating tokens. */
const authEngine = AuthenticationEngine.getInstance();

/**
 * Extracts normalized authorization data from a bearer access token and attaches it to the Express request.
 *
 * When the request contains an `Authorization` header in the form `Bearer <access-token>`, the token's authorization claims are processed and assigned to `request.bearerAuthorizationData`.
 *
 * If the authorization header is missing, does not use the Bearer scheme, or does not contain exactly one token value, `request.bearerAuthorizationData` remains `undefined` and the request continues.
 *
 * This middleware does not cryptographically validate the token. Place `newAuthenticationMiddleware()` before this middleware whenever the extracted authorization data will be trusted for an access-control decision.
 *
 * A bearer-formatted token is decoded by `AuthenticationEngine.getAccessTokenAuthzData()`. That method throws when the value is not a decodable JWT, does not contain the expected Microsoft Entra access-token claims, or contains an issuer from which a tenant ID cannot be extracted. Register an Express error handler after routes using this middleware.
 * @example
 * app.get('/api/profile', newAuthenticationMiddleware([tenantId], [clientId]), extractAuthZ, (request, response) => {
 * if (!request.bearerAuthorizationData) {
 *    response.status(500).json({ 'error': 'Authorization data was not extracted.' });
 *    return;
 * }
 *     response.json({ 'subjectId': request.bearerAuthorizationData.subjectId, 'tenantId': request.bearerAuthorizationData.tenantId, 'permissions': request.bearerAuthorizationData.permissionList });
 * });
 * @example
 * app.get('/api/catalog', extractAuthZ, (request, response) => {
 *     response.json({ 'authenticated': request.bearerAuthorizationData !== undefined, 'subjectId': request.bearerAuthorizationData?.subjectId, 'results': [] });
 * });
 * @remarks
 * This middleware performs authorization-data extraction only. It does not validate the token's signature, issuer metadata, audience, permitted tenant, or validity window.
 * Claims extracted from non-validated token must not be used to grant access, return protected data, or perform privileged operations.
 * @param request Incoming Express request. When extraction succeeds, `request.bearerAuthorizationData` contains the normalized authorization data.
 * @param _response Express response. This middleware does not read from or write to the response.
 * @param next Function that continues the Express middleware pipeline.
 * @throws {TypeError} Thrown when the header has the expected Bearer format but its token cannot be decoded, does not contain the expected Microsoft Entra access-token claims, or contains an invalid issuer.
 * @see AuthenticationEngine.getAccessTokenAuthzData
 * @see newAuthenticationMiddleware
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
