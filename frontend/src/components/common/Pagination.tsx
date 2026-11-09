/*
 * Server-side pagination controls.
 *
 * The API is the source of truth for `total` and `has_more`; the frontend
 * never guesses how many records exist and never loads the whole dataset.
 */

import type { Pagination as PaginationMeta } from '../../api/types';
import { formatCount, pluralise } from '../../lib/format';
import { PAGE_SIZE_OPTIONS } from '../../lib/constants';

interface PaginationProps {
  pagination: PaginationMeta;
  /** Noun used in the status line, for example "threats". */
  itemLabel: string;
  onOffsetChange: (offset: number) => void;
  onLimitChange?: (limit: number) => void;
  isBusy?: boolean;
}

export function Pagination({
  pagination,
  itemLabel,
  onOffsetChange,
  onLimitChange,
  isBusy = false,
}: PaginationProps) {
  const { limit, offset, total, returned, has_more: hasMore } = pagination;

  const first = total === 0 ? 0 : offset + 1;
  const last = offset + returned;
  const canGoBack = offset > 0;

  return (
    <nav className="tp-pagination" aria-label={`${itemLabel} pagination`}>
      <p className="tp-pagination__status" aria-live="polite">
        {total === 0
          ? `No ${itemLabel}`
          : `Showing ${formatCount(first)}–${formatCount(last)} of ${formatCount(total)} ${itemLabel}`}
      </p>

      <div className="tp-pagination__controls">
        {onLimitChange ? (
          <label className="tp-field">
            <span className="tp-field__hint">Per page</span>
            <select
              className="tp-select"
              value={limit}
              disabled={isBusy}
              onChange={(event) => onLimitChange(Number(event.target.value))}
            >
              {PAGE_SIZE_OPTIONS.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        <button
          type="button"
          className="tp-button tp-button--quiet tp-button--small"
          disabled={!canGoBack || isBusy}
          onClick={() => onOffsetChange(Math.max(0, offset - limit))}
        >
          Previous
        </button>

        <button
          type="button"
          className="tp-button tp-button--quiet tp-button--small"
          disabled={!hasMore || isBusy}
          onClick={() => onOffsetChange(offset + limit)}
        >
          Next
        </button>
      </div>

      <span className="visually-hidden">
        {hasMore
          ? `More ${itemLabel} are available.`
          : `This is the last page of ${pluralise(total, itemLabel.replace(/s$/, ''))}.`}
      </span>
    </nav>
  );
}
