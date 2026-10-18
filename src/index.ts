// Export the auth engine for general consumption
export { AuthenticationEngine } from './core/Authentication.js';

// Export the authN middleware for Express.js
export { newAuthenticationMiddleware } from './core/middleware/AuthN.js';

// Export the authZ middleware for Express.js
export { extractAuthZ } from './core/middleware/AuthZ.js';
