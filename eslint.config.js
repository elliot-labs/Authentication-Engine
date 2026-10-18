import { defineConfig } from 'eslint/config';
import { eslintConfig as baseConfig } from '@software-hardware-integration-lab/development-utilities/optimized/lint/base.js';

// Linting configuration used for the runtime and UI as defined by SHI.
export default defineConfig([baseConfig]);
