import { describe, expect, it, vi } from "vitest";

import { parseEventStreamFrame, reconnectDelayMs, runBoundedEventStream } from "./eventStream";

describe("bounded event stream", () => {
  it("parses an invalidation frame and ignores comments", () => {
    const frame = parseEventStreamFrame(': heartbeat\nid: 42\nevent: invalidate\ndata: {"caseId":"CASE-1"}');
    expect(frame).toEqual({ id: "42", event: "invalidate", data: '{"caseId":"CASE-1"}' });
  });

  it("bounds reconnect backoff and jitter", () => {
    expect(reconnectDelayMs(1, () => 0.5)).toBe(1_000);
    expect(reconnectDelayMs(4, () => 0.5)).toBe(10_000);
    expect(reconnectDelayMs(99, () => 0.5)).toBe(30_000);
  });

  it("authenticates with a header and aborts after an invalidation", async () => {
    const controller = new AbortController();
    const event = 'id: 7\nevent: invalidate\ndata: {"id":"7","type":"job.completed","caseId":"CASE-1","captureJobId":"","jobId":"job-1","occurredAt":"2026-08-09T00:00:00Z"}\n\n';
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer access-token");
      return new Response(event, { status: 200, headers: { "Content-Type": "text/event-stream" } });
    }) as unknown as typeof fetch;
    const onInvalidate = vi.fn(() => controller.abort());
    await runBoundedEventStream({
      url: "/api/events/stream?caseRef=route-ref",
      getAccessToken: () => "access-token",
      signal: controller.signal,
      onInvalidate,
      fetchImpl,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(onInvalidate).toHaveBeenCalledWith(expect.objectContaining({ id: "7", caseId: "CASE-1", jobId: "job-1" }));
  });

  it("stops reconnecting when authentication is rejected", async () => {
    const onUnauthorized = vi.fn();
    const fetchImpl = vi.fn(async () => new Response(null, { status: 401 })) as unknown as typeof fetch;
    await runBoundedEventStream({
      url: "/api/events/stream?caseRef=route-ref",
      getAccessToken: () => "expired-token",
      signal: new AbortController().signal,
      onInvalidate: vi.fn(),
      onUnauthorized,
      fetchImpl,
    });
    expect(onUnauthorized).toHaveBeenCalledOnce();
    expect(fetchImpl).toHaveBeenCalledOnce();
  });
});
