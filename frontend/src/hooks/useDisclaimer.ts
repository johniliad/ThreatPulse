/*
 * Disclaimer acceptance.
 *
 * The reader must acknowledge the terms of use before the data pages open, and the
 * acknowledgement is remembered so it is asked once per browser rather than on
 * every visit.
 *
 * The stored value carries the disclaimer version. If the wording changes, the
 * version changes with it and the acknowledgement is asked again — a stale
 * acceptance of different terms is not an acceptance of the current ones.
 *
 * Storage is wrapped because it can throw: Safari in private mode raises on write,
 * and some browsers raise on read when storage is disabled entirely. A failure to
 * remember is not a failure to consent, so a storage error degrades to asking again
 * rather than to a broken page.
 */

import { useCallback, useState } from 'react';
import { DISCLAIMER_VERSION } from '../lib/legal';

const STORAGE_KEY = 'threatpulse.disclaimer.accepted';

function readAccepted(): boolean {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);

    return stored === DISCLAIMER_VERSION;
  } catch {
    return false;
  }
}

export interface DisclaimerAcceptance {
  accepted: boolean;
  accept: () => void;
}

export function useDisclaimer(): DisclaimerAcceptance {
  const [accepted, setAccepted] = useState<boolean>(() => readAccepted());

  const accept = useCallback(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, DISCLAIMER_VERSION);
    } catch {
      // Not remembered, but still accepted for this session.
    }

    setAccepted(true);
  }, []);

  return { accepted, accept };
}
