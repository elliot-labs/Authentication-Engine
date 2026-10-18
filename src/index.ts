// Export the auth engine for general consumption
export { AuthenticationEngine } from './Authentication.js';

// Export the authN middleware for Express.js
export { newAuthenticationMiddleware } from './middleware/AuthN.js';

// Export the authZ middleware for Express.js
export { extractAuthZ } from './middleware/AuthZ.js';
