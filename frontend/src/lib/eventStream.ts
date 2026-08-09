export const EVENT_STREAM_RECONNECT_DELAYS_MS = [1_000, 2_000, 5_000, 10_000, 30_000] as const;

export type NetraInvalidationEvent = {
  id: string;
  type: string;
  caseId: string;
  captureJobId: string;
  jobId: string;
  occurredAt: string;
};

type EventStreamOptions = {
  url: string;
  getAccessToken: () => string;
  signal: AbortSignal;
  onInvalidate: (event: NetraInvalidationEvent) => void;
  onUnauthorized?: () => void;
  fetchImpl?: typeof fetch;
  random?: () => number;
};

export function parseEventStreamFrame(frame: string) {
  let id = "";
  let event = "message";
  const data: string[] = [];
  for (const rawLine of frame.split(/\r?\n/)) {
    if (!rawLine || rawLine.startsWith(":")) continue;
    const separator = rawLine.indexOf(":");
    const field = separator === -1 ? rawLine : rawLine.slice(0, separator);
    const value = separator === -1 ? "" : rawLine.slice(separator + 1).replace(/^ /, "");
    if (field === "id") id = value;
    else if (field === "event") event = value;
    else if (field === "data") data.push(value);
  }
  return { id, event, data: data.join("\n") };
}

function waitForReconnect(delayMs: number, signal: AbortSignal) {
  return new Promise<void>((resolve) => {
    if (signal.aborted) return resolve();
    const timer = window.setTimeout(resolve, delayMs);
    signal.addEventListener("abort", () => {
      window.clearTimeout(timer);
      resolve();
    }, { once: true });
  });
}

export function reconnectDelayMs(failures: number, random = Math.random) {
  const index = Math.max(0, Math.min(failures - 1, EVENT_STREAM_RECONNECT_DELAYS_MS.length - 1));
  return Math.round(EVENT_STREAM_RECONNECT_DELAYS_MS[index] * (0.9 + random() * 0.2));
}

export async function runBoundedEventStream(options: EventStreamOptions) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const random = options.random ?? Math.random;
  let lastEventId = "";
  let failures = 0;

  while (!options.signal.aborted) {
    const token = options.getAccessToken();
    if (!token) return;
    try {
      const response = await fetchImpl(options.url, {
        headers: {
          Accept: "text/event-stream",
          Authorization: `Bearer ${token}`,
          ...(lastEventId ? { "Last-Event-ID": lastEventId } : {}),
        },
        cache: "no-store",
        signal: options.signal,
      });
      if (response.status === 401) {
        options.onUnauthorized?.();
        return;
      }
      if (!response.ok || !response.body) throw new Error(`SSE failed with ${response.status}`);
      failures = 0;
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!options.signal.aborted) {
        const { done, value } = await reader.read();
        buffer += decoder.decode(value, { stream: !done });
        let boundary = buffer.search(/\r?\n\r?\n/);
        while (boundary >= 0) {
          const match = buffer.match(/\r?\n\r?\n/);
          const separatorLength = match?.[0].length ?? 2;
          const frame = parseEventStreamFrame(buffer.slice(0, boundary));
          buffer = buffer.slice(boundary + separatorLength);
          if (frame.id) lastEventId = frame.id;
          if (frame.event === "invalidate" && frame.data) {
            try {
              const payload = JSON.parse(frame.data) as NetraInvalidationEvent;
              options.onInvalidate(payload);
            } catch {
              // Ignore malformed untrusted event data; the periodic refresh remains authoritative.
            }
          }
          boundary = buffer.search(/\r?\n\r?\n/);
        }
        if (done) break;
      }
    } catch (error) {
      if (options.signal.aborted || (error instanceof DOMException && error.name === "AbortError")) return;
      failures += 1;
    }
    if (options.signal.aborted) return;
    await waitForReconnect(reconnectDelayMs(failures, random), options.signal);
  }
}
