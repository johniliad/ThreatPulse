/*
 * ThreatPulse API error taxonomy.
 *
 * Every failure mode the UI needs to distinguish is represented explicitly so
 * that components can render an honest, useful state instead of a generic
 * error string.
 */

export type ApiErrorKind =
  /** The request never reached the API (offline, DNS, CORS, connection reset). */
  | 'network'
  /** The request exceeded the client-side timeout. */
  | 'timeout'
  /** The request was cancelled by the caller (navigation, unmount, new query). */
  | 'aborted'
  /** The caller supplied an identifier or filter the API does not accept. */
  | 'invalid-request'
  /** The API answered with a non-success HTTP status. */
  | 'http'
  /** The API answered, but the payload did not match the documented contract. */
  | 'invalid-response';

interface ApiErrorOptions {
  status?: number | null;
  detail?: string | null;
  cause?: unknown;
}

export class ApiError extends Error {
  readonly kind: ApiErrorKind;

  /** HTTP status code, when the failure came from an HTTP response. */
  readonly status: number | null;

  /** Server-provided message, when the API returned one. */
  readonly detail: string | null;

  constructor(kind: ApiErrorKind, message: string, options: ApiErrorOptions = {}) {
    super(message);

    this.name = 'ApiError';
    this.kind = kind;
    this.status = options.status ?? null;
    this.detail = options.detail ?? null;

    if (options.cause !== undefined) {
      this.cause = options.cause;
    }
  }

  /** True when retrying the same request could plausibly succeed. */
  get isRetryable(): boolean {
    if (this.kind === 'network' || this.kind === 'timeout') {
      return true;
    }

    return this.status !== null && this.status >= 500;
  }

  /** True when the request was cancelled deliberately and should be ignored. */
  get isAbort(): boolean {
    return this.kind === 'aborted';
  }

  /** Message suitable for display to a security professional. */
  get userMessage(): string {
    switch (this.kind) {
      case 'network':
        return 'The ThreatPulse API could not be reached. Check your connection and try again.';
      case 'timeout':
        return 'The ThreatPulse API did not respond in time. Try again.';
      case 'aborted':
        return 'The request was cancelled.';
      case 'invalid-request':
        return 'The request was rejected before it was sent, because the supplied identifier or filter is not one the ThreatPulse API accepts.';
      case 'http':
        if (this.status === 400) {
          return this.detail
            ? `The API rejected the request: ${this.detail}`
            : 'The API rejected the request as invalid.';
        }

        if (this.status === 404) {
          return 'The requested record was not found in the ThreatPulse API.';
        }

        if (this.status === 405) {
          return 'The API rejected the request method.';
        }

        if (this.status === 403) {
          return 'The API refused the request. This deployment restricts access to that endpoint, or the request did not arrive through the expected front end.';
        }

        if (this.status === 429) {
          return 'The ThreatPulse API is rate limiting requests. Please wait a moment and try again.';
        }

        if (this.status !== null && this.status >= 500) {
          return 'The ThreatPulse API reported an internal error. This is a server-side problem, not a problem with your request.';
        }

        return this.detail
          ? `The API returned an unexpected response: ${this.detail}`
          : 'The API returned an unexpected response.';
      case 'invalid-response':
        return 'The API responded, but the payload did not match the documented ThreatPulse contract. The data was not displayed to avoid presenting it as trustworthy.';
      default:
        return 'An unexpected error occurred.';
    }
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

/** Normalises anything thrown by the API layer into an ApiError. */
export function toApiError(error: unknown): ApiError {
  if (isApiError(error)) {
    return error;
  }

  if (error instanceof DOMException && error.name === 'AbortError') {
    return new ApiError('aborted', 'The request was cancelled.');
  }

  if (error instanceof Error) {
    return new ApiError('network', error.message, { cause: error });
  }

  return new ApiError('network', 'Unknown API failure.', { cause: error });
}

/** Convenience helper used by hooks to ignore cancellations. */
export function isAbortError(error: unknown): boolean {
  return isApiError(error) && error.isAbort;
}
