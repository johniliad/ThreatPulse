/*
 * Application entry point.
 *
 * BrowserRouter is used with a real server-side rewrite (public/.htaccess), so
 * URLs are shareable and canonical rather than hash-based.
 */

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { App } from './App';

import './styles/tokens.css';
import './styles/base.css';
import './styles/components.css';

const container = document.getElementById('root');

if (!container) {
  throw new Error(
    'ThreatPulse could not start: the #root container is missing from index.html.'
  );
}

createRoot(container).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>
);
