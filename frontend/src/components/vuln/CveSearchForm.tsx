/*
 * CVE search field.
 *
 * The identifier is validated with the same rule the API applies before any
 * request is sent, so an invalid value produces an immediate, local message
 * instead of a wasted round trip and an HTTP 400.
 */

import { useEffect, useId, useState, type FormEvent } from 'react';
import { isValidCveId } from '../../api/validate';

interface CveSearchFormProps {
  value: string;
  onSubmit: (cve: string) => void;
  onClear: () => void;
  hint?: string;
  disabled?: boolean;
  /** Set when the URL itself contained an unusable CVE value. */
  urlInvalid?: boolean;
}

export function CveSearchForm({
  value,
  onSubmit,
  onClear,
  hint = 'Resolves a CVE to its ThreatPulse threat records.',
  disabled = false,
  urlInvalid = false,
}: CveSearchFormProps) {
  const inputId = useId();
  const errorId = `${inputId}-error`;
  const hintId = `${inputId}-hint`;

  const [draft, setDraft] = useState(value);
  const [error, setError] = useState<string | null>(
    urlInvalid ? 'The link contained a CVE identifier that is not valid.' : null
  );

  useEffect(() => {
    setDraft(value);
  }, [value]);

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const trimmed = draft.trim();

    if (trimmed === '') {
      setError(null);
      onClear();

      return;
    }

    if (!isValidCveId(trimmed)) {
      setError('Enter a CVE identifier in the form CVE-YYYY-NNNN.');

      return;
    }

    setError(null);
    onSubmit(trimmed.toUpperCase());
  }

  return (
    <form className="tp-field" onSubmit={handleSubmit} noValidate>
      <label htmlFor={inputId}>CVE identifier</label>
      <span className="tp-field__hint" id={hintId}>
        {hint}
      </span>

      <div className="tp-inline">
        <input
          id={inputId}
          className="tp-input tp-input--mono"
          type="text"
          inputMode="text"
          autoComplete="off"
          spellCheck={false}
          placeholder="CVE-2026-109619"
          value={draft}
          disabled={disabled}
          aria-invalid={error !== null}
          aria-describedby={error ? `${hintId} ${errorId}` : hintId}
          onChange={(event) => {
            setDraft(event.target.value);

            if (error) {
              setError(null);
            }
          }}
        />

        <button type="submit" className="tp-button tp-button--small" disabled={disabled}>
          Find CVE
        </button>

        {value !== '' ? (
          <button
            type="button"
            className="tp-button tp-button--quiet tp-button--small"
            disabled={disabled}
            onClick={() => {
              setDraft('');
              setError(null);
              onClear();
            }}
          >
            Clear
          </button>
        ) : null}
      </div>

      {error ? (
        <span className="tp-field__hint" id={errorId} role="alert">
          {error}
        </span>
      ) : null}
    </form>
  );
}
