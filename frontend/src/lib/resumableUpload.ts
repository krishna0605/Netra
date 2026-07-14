import { defaultOptions, Upload } from "tus-js-client";

export type DirectUploadSession = {
  id: string;
  caseId: string;
  status: string;
  filename: string;
  expectedSizeBytes: number;
  actualSizeBytes: number | null;
  evidenceType: string;
  contentType: string;
  bucketName: string;
  objectName: string;
  fingerprint: string;
  expiresAt: string;
  finalizedAt: string | null;
  failureCode: string;
  jobId: string;
  idempotentReplay: boolean;
  tus: {
    endpoint: string;
    chunkSizeBytes: number;
    retryDelaysMs: number[];
    upsert: false;
  };
};

export type ResumableProgress = {
  bytesUploaded: number;
  bytesTotal: number;
  percentage: number;
};

export type ResumableUploadHandle = {
  completion: Promise<void>;
  pause: () => Promise<void>;
  resume: () => void;
  cancelLocal: () => Promise<void>;
  isPaused: () => boolean;
};

type ResumableUploadCallbacks = {
  onProgress: (progress: ResumableProgress) => void;
  onRetry: (attempt: number, message: string) => void;
  onResumed: () => void;
};

export function beginResumableUpload(
  file: File,
  session: DirectUploadSession,
  accessToken: string,
  callbacks: ResumableUploadCallbacks,
): ResumableUploadHandle {
  let paused = false;
  let settled = false;
  let resolveCompletion: () => void = () => undefined;
  let rejectCompletion: (error: Error) => void = () => undefined;
  const completion = new Promise<void>((resolve, reject) => {
    resolveCompletion = resolve;
    rejectCompletion = reject;
  });

  const upload = new Upload(file, {
    endpoint: session.tus.endpoint,
    retryDelays: session.tus.retryDelaysMs,
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
    uploadDataDuringCreation: true,
    storeFingerprintForResuming: true,
    removeFingerprintOnSuccess: true,
    chunkSize: session.tus.chunkSizeBytes,
    metadata: {
      bucketName: session.bucketName,
      objectName: session.objectName,
      contentType: file.type || session.contentType || "application/octet-stream",
      cacheControl: "no-store",
    },
    fingerprint: async () => `netra-${session.id}-${session.fingerprint}`,
    onProgress: (bytesUploaded, bytesTotal) => {
      callbacks.onProgress({
        bytesUploaded,
        bytesTotal,
        percentage: bytesTotal > 0 ? (bytesUploaded / bytesTotal) * 100 : 0,
      });
    },
    onShouldRetry: (error, retryAttempt, options) => {
      callbacks.onRetry(retryAttempt + 1, error.message);
      return defaultOptions.onShouldRetry?.(error, retryAttempt, options) ?? false;
    },
    onError: (error) => {
      if (settled || paused) return;
      settled = true;
      rejectCompletion(error instanceof Error ? error : new Error(String(error)));
    },
    onSuccess: () => {
      if (settled) return;
      settled = true;
      resolveCompletion();
    },
  });

  void upload.findPreviousUploads().then((previousUploads) => {
    if (previousUploads.length > 0) {
      upload.resumeFromPreviousUpload(previousUploads[0]);
      callbacks.onResumed();
    }
    upload.start();
  }).catch((error: unknown) => {
    if (settled) return;
    settled = true;
    rejectCompletion(error instanceof Error ? error : new Error(String(error)));
  });

  return {
    completion,
    pause: async () => {
      if (settled || paused) return;
      paused = true;
      await upload.abort(false);
    },
    resume: () => {
      if (settled || !paused) return;
      paused = false;
      upload.start();
    },
    cancelLocal: async () => {
      if (settled) return;
      paused = true;
      settled = true;
      await upload.abort(false);
      rejectCompletion(new Error("Upload canceled in this browser. The quarantined partial upload will expire automatically."));
    },
    isPaused: () => paused,
  };
}
