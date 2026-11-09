/*
 * Shared ThreatPulse constants.
 *
 * Every value here is either an API whitelist value or a ThreatPulse product
 * definition taken from the requirements. Nothing is invented.
 */

import type { ExploitationStatus, Severity } from '../api/types';

/** Values the API accepts for the `severity` filter, in display order. */
export const SEVERITY_VALUES: readonly Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
];

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
  unknown: 'Unreported severity',
};

/** Values the API accepts for the `exploitation_status` filter. */
export const EXPLOITATION_VALUES: readonly ExploitationStatus[] = [
  'confirmed',
  'suspected',
  'unknown',
  'not_exploited',
];

export const EXPLOITATION_LABELS: Record<ExploitationStatus, string> = {
  confirmed: 'Exploitation confirmed',
  suspected: 'Exploitation suspected',
  unknown: 'Exploitation status unknown',
  not_exploited: 'Not known to be exploited',
};

/** Short labels for dense list rows. */
export const EXPLOITATION_SHORT_LABELS: Record<ExploitationStatus, string> = {
  confirmed: 'Confirmed',
  suspected: 'Suspected',
  unknown: 'Unknown',
  not_exploited: 'Not exploited',
};

export const CONFIDENCE_LABELS: Record<string, string> = {
  high: 'High confidence',
  medium: 'Medium confidence',
  low: 'Low confidence',
  unknown: 'Confidence not reported',
};

export const DEFAULT_PAGE_SIZE = 25;

export const PAGE_SIZE_OPTIONS = [10, 25, 50, 100] as const;

/** Count-only requests use limit=1 to keep the payload minimal. */
export const COUNT_QUERY_LIMIT = 1;

/** The API's own cache window, used to explain data age to the user. */
export const API_CACHE_SECONDS = 60;

export const PRODUCT_NAME = 'ThreatPulse';

export const PRODUCT_POSITIONING =
  'Transparent Cyber Threat Intelligence';

export const PRODUCT_PROPOSITION =
  'Turning global threat signals into prioritised intelligence, with every claim traceable to its source.';

export const PRODUCT_QUESTION = 'What deserves attention now — and why?';

/** The ecosystem this product belongs to. */
export const ECOSYSTEM_URL = 'https://www.iliadis.net';
export const ECOSYSTEM_LABEL = 'iliadis.net';

/*
 * The author.
 *
 * Every value below is taken from the author's own site, https://www.iliadis.net,
 * so the product states who built it in the author's own words rather than in
 * marketing copy. If those fields change there, they should change here.
 */
export const AUTHOR_NAME = 'Dr. John Iliadis';
export const AUTHOR_NAME_GREEK = 'Γιάννης Ηλιάδης';
export const AUTHOR_TITLE = 'Technology & Cybersecurity Executive';
export const AUTHOR_URL = ECOSYSTEM_URL;
export const AUTHOR_LOCATION = 'Athens, Greece';
export const AUTHOR_ROLE = 'IT Infrastructure Director, TEIRESIAS S.A.';

/** Verbatim from iliadis.net. */
export const AUTHOR_CREDENTIALS =
  'PhD · CISSP · CISM · CRISC · C|CISO · COBIT · ITIL · CMgr MCMI';

/** The author's own one-sentence description, verbatim from iliadis.net. */
export const AUTHOR_DESCRIPTION =
  'Dr. John Iliadis brings 20+ years of technology and cybersecurity leadership across enterprise infrastructure, cyber operations, transformation and resilience in mission-critical environments.';

export const AUTHOR_EDUCATION = [
  {
    year: '2008',
    award: 'PhD, Information & Communication Systems Security',
    institution: 'University of the Aegean',
  },
  {
    year: '1999',
    award: 'MSc, Information Security',
    institution: 'Royal Holloway College, University of London',
  },
] as const;

/**
 * The product's licence.
 *
 * `null` means no licence has been declared yet, which is the current state: the
 * repository has no LICENSE file. Nothing in the product therefore claims that it
 * is open source — the author strip and the footer say "public threat
 * intelligence", and the About page says plainly that no licence is declared yet.
 *
 * This is deliberate and was once the other way round: the strip used to state
 * "open-source" as the product's intent while the About page promised the claim
 * would not be made anywhere before a LICENSE file existed. Two pages asserting
 * opposite things is worse than either position alone, so the claim was removed.
 * It is restored by dropping a LICENSE file in and setting this constant — not by
 * softening the wording on the one page that talks about licensing.
 */
export const PRODUCT_LICENCE: string | null = null;

/**
 * The public source repository, if there is one.
 *
 * `null` today: the repository has no remote, so there is nothing public to link.
 * The strip renders the link only when this is set, rather than linking somewhere
 * that does not exist. Publishing the repository is the single highest-value thing
 * available to this product's credibility, because it lets a reader check every
 * claim on the page against the code that makes it.
 */
export const PRODUCT_REPOSITORY_URL: string | null = null;
