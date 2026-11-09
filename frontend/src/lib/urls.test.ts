/*
 * URL and link-safety tests.
 *
 * The security-critical assertions here are that unsafe schemes are never
 * emitted as links and that a malformed CVE can never reach an outbound path.
 */

import { describe, expect, it } from 'vitest';
import {
  cisaKevUrl,
  nvdUrlForCve,
  safeExternalUrl,
  splitExternalLinks,
  threatsPath,
  vulnerabilitiesPath,
} from './urls';

describe('safeExternalUrl', () => {
  it('accepts absolute http and https URLs', () => {
    expect(safeExternalUrl('https://nvd.nist.gov/vuln/detail/CVE-2026-109619')).toBe(
      'https://nvd.nist.gov/vuln/detail/CVE-2026-109619'
    );
    expect(safeExternalUrl('http://example.org/')).toBe('http://example.org/');
  });

  it('rejects dangerous and non-absolute schemes', () => {
    expect(safeExternalUrl('javascript:alert(1)')).toBeNull();
    expect(safeExternalUrl('data:text/html;base64,PHNjcmlwdD4=')).toBeNull();
    expect(safeExternalUrl('vbscript:msgbox(1)')).toBeNull();
    expect(safeExternalUrl('/relative/path')).toBeNull();
  });

  it('rejects empty and non-string values', () => {
    expect(safeExternalUrl('')).toBeNull();
    expect(safeExternalUrl('   ')).toBeNull();
    expect(safeExternalUrl(null)).toBeNull();
    expect(safeExternalUrl(undefined)).toBeNull();
  });

  it('trims surrounding whitespace', () => {
    expect(safeExternalUrl('  https://example.org/  ')).toBe(
      'https://example.org/'
    );
  });
});

describe('nvdUrlForCve', () => {
  it('builds a reference for a valid CVE', () => {
    expect(nvdUrlForCve('CVE-2026-109619')).toBe(
      'https://nvd.nist.gov/vuln/detail/CVE-2026-109619'
    );
  });

  it('normalises case', () => {
    expect(nvdUrlForCve('cve-1999-0001')).toBe(
      'https://nvd.nist.gov/vuln/detail/CVE-1999-0001'
    );
  });

  it('returns null for anything that is not a CVE identifier', () => {
    expect(nvdUrlForCve('CVE-2026-109619/../evil')).toBeNull();
    expect(nvdUrlForCve('not-a-cve')).toBeNull();
    expect(nvdUrlForCve(null)).toBeNull();
  });
});

describe('threatsPath', () => {
  it('returns the bare path when nothing is filtered', () => {
    expect(threatsPath()).toBe('/threats');
    expect(threatsPath({ severity: 'unknown' })).toBe('/threats');
  });

  it('serialises filters and pagination', () => {
    expect(
      threatsPath({
        severity: 'critical',
        exploitation: 'confirmed',
        cve: 'cve-2026-109619',
        limit: 50,
        offset: 25,
      })
    ).toBe(
      '/threats?severity=critical&exploitation=confirmed&cve=CVE-2026-109619&limit=50&offset=25'
    );
  });

  it('omits the default page size and a zero offset', () => {
    expect(threatsPath({ limit: 25, offset: 0 })).toBe('/threats');
  });
});

describe('vulnerabilitiesPath', () => {
  it('serialises a CVE lookup and the KEV filter', () => {
    expect(vulnerabilitiesPath({ cve: 'CVE-2026-109619' })).toBe(
      '/vulnerabilities?cve=CVE-2026-109619'
    );
    expect(vulnerabilitiesPath({ kevOnly: true })).toBe(
      '/vulnerabilities?kev=true'
    );
  });

  it('returns the bare path by default', () => {
    expect(vulnerabilitiesPath()).toBe('/vulnerabilities');
  });
});

describe('splitExternalLinks', () => {
  it('splits prose into text and validated links', () => {
    const segments = splitExternalLinks(
      'See https://nvd.nist.gov/vuln/detail/CVE-2026-109619 for details.'
    );

    expect(segments).toHaveLength(3);
    expect(segments[1]?.type).toBe('link');
    expect(segments[1]?.href).toBe(
      'https://nvd.nist.gov/vuln/detail/CVE-2026-109619'
    );
    expect(segments[2]?.text).toBe(' for details.');
  });

  it('drops trailing punctuation from the href but keeps the visible text', () => {
    const segments = splitExternalLinks('Reference: https://example.org/x).');

    const link = segments.find((segment) => segment.type === 'link');

    expect(link?.href).toBe('https://example.org/x');
    expect(link?.text).toBe('https://example.org/x).');
  });

  it('leaves non-http schemes as plain text', () => {
    const segments = splitExternalLinks('Ignore javascript:alert(1) entirely.');

    expect(segments.every((segment) => segment.type === 'text')).toBe(true);
  });

  it('returns a single text segment when there is no URL', () => {
    const segments = splitExternalLinks('No links here.');

    expect(segments).toHaveLength(1);
    expect(segments[0]?.type).toBe('text');
  });

  it('exposes the CISA catalogue URL used for provenance links', () => {
    expect(cisaKevUrl()).toContain('cisa.gov');
  });
});
