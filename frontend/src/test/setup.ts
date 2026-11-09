/*
 * Vitest setup.
 *
 * Testing Library's automatic cleanup is registered manually because the
 * project runs Vitest without injected globals (tests import from 'vitest'
 * explicitly, which keeps `tsc` honest about what is available).
 */

import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

afterEach(() => {
  cleanup();
});
