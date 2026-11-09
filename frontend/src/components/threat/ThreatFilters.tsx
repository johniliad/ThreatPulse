/*
 * Threat filters.
 *
 * Filter changes are written to the URL by the calling page, so every view is
 * shareable and survives refresh. The CVE field is only offered when the
 * deployed API actually supports CVE filtering.
 */

import { useId } from 'react';
import type { ExploitationStatus, Severity } from '../../api/types';
import {
  EXPLOITATION_LABELS,
  EXPLOITATION_VALUES,
  SEVERITY_LABELS,
  SEVERITY_VALUES,
} from '../../lib/constants';
import type { ThreatFilters as ThreatFilterState } from '../../hooks/useFilters';
import { CveSearchForm } from '../vuln/CveSearchForm';

interface Option<T extends string> {
  value: T | 'all';
  label: string;
}

interface RadioGroupProps<T extends string> {
  legend: string;
  name: string;
  options: Array<Option<T>>;
  value: T | 'all';
  disabled?: boolean;
  onChange: (value: T | 'all') => void;
}

function RadioGroup<T extends string>({
  legend,
  name,
  options,
  value,
  disabled = false,
  onChange,
}: RadioGroupProps<T>) {
  const groupId = useId();

  return (
    <fieldset className="tp-field tp-filters__legend">
      <legend>{legend}</legend>
      <div className="tp-filters__options">
        {options.map((option) => {
          const optionId = `${groupId}-${option.value}`;
          const isActive = option.value === value;

          return (
            <label
              key={option.value}
              className={isActive ? 'tp-radio tp-radio--active' : 'tp-radio'}
              htmlFor={optionId}
            >
              <input
                id={optionId}
                type="radio"
                name={name}
                value={option.value}
                checked={isActive}
                disabled={disabled}
                onChange={() => onChange(option.value)}
              />
              {option.label}
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

interface ThreatFiltersProps {
  filters: ThreatFilterState;
  onChange: (patch: Partial<ThreatFilterState>) => void;
  onReset: () => void;
  /** True when the deployed API supports the `cve` filter. */
  cveSearchEnabled: boolean;
  isBusy?: boolean;
}

export function ThreatFilters({
  filters,
  onChange,
  onReset,
  cveSearchEnabled,
  isBusy = false,
}: ThreatFiltersProps) {
  const severityOptions: Array<Option<Severity>> = [
    { value: 'all', label: 'All severities' },
    ...SEVERITY_VALUES.map((severity) => ({
      value: severity,
      label: SEVERITY_LABELS[severity],
    })),
  ];

  const exploitationOptions: Array<Option<ExploitationStatus>> = [
    { value: 'all', label: 'Any exploitation status' },
    ...EXPLOITATION_VALUES.map((status) => ({
      value: status,
      label: EXPLOITATION_LABELS[status],
    })),
  ];

  const hasActiveFilter =
    filters.severity !== 'all' ||
    filters.exploitation !== 'all' ||
    filters.cve !== '';

  return (
    <div className="tp-filters">
      <RadioGroup
        legend="Severity"
        name="severity"
        options={severityOptions}
        value={filters.severity}
        disabled={isBusy}
        onChange={(value) => onChange({ severity: value })}
      />

      <RadioGroup
        legend="Exploitation status"
        name="exploitation"
        options={exploitationOptions}
        value={filters.exploitation}
        disabled={isBusy}
        onChange={(value) => onChange({ exploitation: value })}
      />

      {cveSearchEnabled ? (
        <CveSearchForm
          value={filters.cve}
          disabled={isBusy}
          urlInvalid={filters.invalidCve}
          hint="Filter the threat list by the CVE it relates to."
          onSubmit={(cve) => onChange({ cve })}
          onClear={() => onChange({ cve: '' })}
        />
      ) : null}

      <div className="tp-filters__actions">
        <button
          type="button"
          className="tp-button tp-button--quiet tp-button--small"
          onClick={onReset}
          disabled={isBusy || !hasActiveFilter}
        >
          Reset filters
        </button>
      </div>
    </div>
  );
}
