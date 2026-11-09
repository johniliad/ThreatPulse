/*
 * Application routes.
 *
 * Each page is code-split, so the initial payload only contains the shell and
 * the dashboard. The API client's own cache and the 60-second server cache keep
 * navigation between pages cheap.
 */

import { Suspense, lazy, type ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { LoadingState } from './components/common/StateBlock';

const DashboardPage = lazy(() =>
  import('./pages/DashboardPage').then((module) => ({
    default: module.DashboardPage,
  }))
);

const ThreatsPage = lazy(() =>
  import('./pages/ThreatsPage').then((module) => ({
    default: module.ThreatsPage,
  }))
);

const ThreatDetailPage = lazy(() =>
  import('./pages/ThreatDetailPage').then((module) => ({
    default: module.ThreatDetailPage,
  }))
);

const VulnerabilitiesPage = lazy(() =>
  import('./pages/VulnerabilitiesPage').then((module) => ({
    default: module.VulnerabilitiesPage,
  }))
);

const SourcesPage = lazy(() =>
  import('./pages/SourcesPage').then((module) => ({
    default: module.SourcesPage,
  }))
);

const ApiPage = lazy(() =>
  import('./pages/ApiPage').then((module) => ({ default: module.ApiPage }))
);

const MethodologyPage = lazy(() =>
  import('./pages/MethodologyPage').then((module) => ({
    default: module.MethodologyPage,
  }))
);


const AboutPage = lazy(() =>
  import('./pages/AboutPage').then((module) => ({
    default: module.AboutPage,
  }))
);

const NotFoundPage = lazy(() =>
  import('./pages/NotFoundPage').then((module) => ({
    default: module.NotFoundPage,
  }))
);

function Page({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Suspense
      fallback={
        <section className="tp-section">
          <div className="container">
            <LoadingState label={label} lines={3} />
          </div>
        </section>
      }
    >
      {children}
    </Suspense>
  );
}

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route
          index
          element={
            <Page label="Loading the dashboard">
              <DashboardPage />
            </Page>
          }
        />
        <Route
          path="threats"
          element={
            <Page label="Loading the threat list">
              <ThreatsPage />
            </Page>
          }
        />
        <Route
          path="threats/:uuid"
          element={
            <Page label="Loading the threat record">
              <ThreatDetailPage />
            </Page>
          }
        />
        <Route
          path="vulnerabilities"
          element={
            <Page label="Loading vulnerability intelligence">
              <VulnerabilitiesPage />
            </Page>
          }
        />
        <Route
          path="sources"
          element={
            <Page label="Loading intelligence sources">
              <SourcesPage />
            </Page>
          }
        />
        <Route
          path="api"
          element={
            <Page label="Loading the API reference">
              <ApiPage />
            </Page>
          }
        />
        <Route
          path="methodology"
          element={
            <Page label="Loading the methodology">
              <MethodologyPage />
            </Page>
          }
        />
        {/*
          The former "How it works" page was merged into Methodology. The route is
          kept as a redirect rather than removed, so a bookmark or an external link
          to it still lands on the content it described.
        */}
        <Route path="how-it-works" element={<Navigate to="/methodology" replace />} />
        <Route
          path="about"
          element={
            <Page label="Loading the about page">
              <AboutPage />
            </Page>
          }
        />
        <Route
          path="*"
          element={
            <Page label="Loading">
              <NotFoundPage />
            </Page>
          }
        />
      </Route>
    </Routes>
  );
}
