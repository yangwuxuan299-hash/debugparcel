import { scanDiagnostics, type ScanResult } from "../lib/sanitize";

type ScanInput = {
  harText?: string;
  consoleText?: string;
  customTerms?: string[];
};

type WorkerRequest = { id: number; input: ScanInput };
type WorkerResponse =
  | { id: number; result: ScanResult }
  | { id: number; error: string };

type WorkerScope = {
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
  postMessage: (message: WorkerResponse) => void;
};

const workerScope = globalThis as unknown as WorkerScope;

workerScope.onmessage = (event) => {
  const { id, input } = event.data;
  try {
    workerScope.postMessage({ id, result: scanDiagnostics(input) });
  } catch (reason) {
    workerScope.postMessage({
      id,
      error: reason instanceof Error ? reason.message : "The files could not be scanned.",
    });
  }
};
