/**
 * Minimal authenticated transport for Google REST APIs.
 *
 * Veil talks to Google over REST rather than pulling in the full client
 * libraries: the credential-handling process should carry as little third-party
 * code as it can (SPEC.md §42). `google-auth-library` is an optional dependency,
 * imported lazily, so an installation that only writes `.env` files never loads
 * it at all.
 *
 * The credential is always placed in a request *body*, never in a URL or a query
 * string (SEC-007), and every request carries an explicit timeout — the broker
 * cannot cancel work that has already left for the network.
 */

export interface GoogleRequest {
  readonly method: 'GET' | 'POST' | 'PATCH';
  readonly url: string;
  readonly body?: unknown;
  readonly timeoutMs: number;
}

export interface GoogleResponse {
  readonly status: number;
  readonly body: unknown;
}

export type GoogleTransport = (request: GoogleRequest) => Promise<GoogleResponse>;

export const SECRET_MANAGER_BASE = 'https://secretmanager.googleapis.com/v1';
export const FIRESTORE_BASE = 'https://firestore.googleapis.com/v1';

/** An error carrying only a provider status code — never a provider message. */
export class GoogleStatusError extends Error {
  constructor(readonly status: number) {
    super(`google_status_${status}`);
    this.name = 'GoogleStatusError';
  }
}

export async function createDefaultTransport(scopes: readonly string[]): Promise<GoogleTransport> {
  let auth: { getAccessToken(): Promise<string | null | undefined> };
  try {
    // Resolved through a variable so the optional dependency is not required at
    // build time: an installation that only writes `.env` files never has it.
    const specifier = 'google-auth-library';
    const { GoogleAuth } = (await import(specifier)) as {
      GoogleAuth: new (options: { scopes: string[] }) => {
        getAccessToken(): Promise<string | null | undefined>;
      };
    };
    auth = new GoogleAuth({ scopes: [...scopes] });
    // Fail here, while we can still report "unavailable" cleanly, rather than
    // half-way through a write.
    await auth.getAccessToken();
  } catch (error) {
    throw new GoogleAuthUnavailableError(error);
  }

  return async ({ method, url, body, timeoutMs }: GoogleRequest): Promise<GoogleResponse> => {
    const token = await auth.getAccessToken();
    const response = await fetch(url, {
      method,
      headers: {
        authorization: `Bearer ${token ?? ''}`,
        'content-type': 'application/json',
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    let parsed: unknown = null;
    try {
      parsed = await response.json();
    } catch {
      parsed = null;
    }
    return { status: response.status, body: parsed };
  };
}

export class GoogleAuthUnavailableError extends Error {
  constructor(override readonly cause: unknown) {
    super('google_auth_unavailable');
    this.name = 'GoogleAuthUnavailableError';
  }
}
