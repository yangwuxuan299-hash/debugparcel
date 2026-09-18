"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Archive,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  CircleAlert,
  Download,
  Eye,
  FileJson2,
  Image as ImageIcon,
  LockKeyhole,
  Plus,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Trash2,
  UploadCloud,
  X,
} from "lucide-react";
import { ScreenshotRedactor } from "@/components/screenshot-redactor";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import {
  findingsByCategory,
  scanDiagnostics,
  type Finding,
  type ScanResult,
} from "@/lib/sanitize";
import { downloadBlob, makeZip, sha256 } from "@/lib/zip";

declare global {
  interface Document {
    modelContext?: {
      registerTool: (
        tool: {
          name: string;
          title?: string;
          description: string;
          inputSchema: object;
          annotations?: { readOnlyHint?: boolean; untrustedContentHint?: boolean };
          execute: (input: unknown) => unknown | Promise<unknown>;
        },
        options?: { signal?: AbortSignal },
      ) => void | Promise<void>;
    };
  }
}

type Step = "import" | "review" | "mask" | "export";
type FileKind = "har" | "console" | "screenshot";
type FileSet = Partial<Record<FileKind, File>>;

const steps: Array<{ id: Step; label: string }> = [
  { id: "import", label: "Import evidence" },
  { id: "review", label: "Review findings" },
  { id: "mask", label: "Mask screenshot" },
  { id: "export", label: "Export parcel" },
];

const fileMeta: Record<FileKind, { label: string; hint: string; icon: typeof FileJson2 }> = {
  har: { label: "Network archive", hint: ".har · up to 50 MB", icon: FileJson2 },
  console: { label: "Console output", hint: ".json, .txt or .log", icon: TerminalSquare },
  screenshot: { label: "Screenshot", hint: ".png, .jpg or .webp", icon: ImageIcon },
};

const demoHar = JSON.stringify({
  log: {
    version: "1.2",
    creator: { name: "DebugParcel demo", version: "1.0" },
    entries: [
      {
        startedDateTime: "2026-09-19T10:00:00.000Z",
        time: 320,
        request: {
          method: "POST",
          url: "https://billing.staging.acme.internal/v1/orders?customer=alice%40example.com&api_key=sk_test_Q7z91Lm2",
          headers: [
            {
              name: "Authorization",
              value: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c3JfNDIifQ.sigSECRET123",
            },
            { name: "Cookie", value: "session=sess_live_4f9c2a7b" },
          ],
          queryString: [
            { name: "customer", value: "alice@example.com" },
            { name: "api_key", value: "sk_test_Q7z91Lm2" },
          ],
          postData: {
            mimeType: "application/json",
            text: '{"userId":"usr_42","email":"alice@example.com"}',
          },
        },
        response: {
          status: 500,
          statusText: "Internal Server Error",
          headers: [{ name: "Set-Cookie", value: "session=sess_live_4f9c2a7b; HttpOnly; Secure" }],
          content: {
            mimeType: "application/json",
            text: '{"ok":false,"ownerEmail":"alice@example.com","userId":"usr_42"}',
          },
        },
        serverIPAddress: "10.0.12.7",
      },
    ],
  },
}, null, 2);

const demoConsole = JSON.stringify([
  {
    timestamp: "2026-09-19T10:00:01.120Z",
    level: "error",
    message: "checkout failed for user=usr_42 email=alice@example.com",
  },
  {
    timestamp: "2026-09-19T10:00:01.140Z",
    level: "debug",
    message: "Authorization=\"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c3JfNDIifQ.sigSECRET123\"",
  },
  {
    timestamp: "2026-09-19T10:00:01.180Z",
    level: "error",
    message: "upstream billing.staging.acme.internal (10.0.12.7); config=/Users/alice/projects/payments/.env",
  },
], null, 2);

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

function detectKind(file: File): FileKind | null {
  const name = file.name.toLowerCase();
  if (name.endsWith(".har")) return "har";
  if (file.type.startsWith("image/") || /\.(png|jpe?g|webp)$/.test(name)) return "screenshot";
  if (/\.(json|txt|log)$/.test(name) || file.type.includes("json") || file.type.startsWith("text/")) {
    return "console";
  }
  return null;
}

function dateSlug(date = new Date()) {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}`;
}

function findingLabel(category: Finding["category"]) {
  return category.replaceAll("_", " ").toLowerCase().replace(/^./, (letter) => letter.toUpperCase());
}

async function demoScreenshot() {
  const canvas = document.createElement("canvas");
  canvas.width = 1280;
  canvas.height = 720;
  const context = canvas.getContext("2d");
  if (!context) throw new Error("Canvas is unavailable.");
  context.fillStyle = "#eef2ee";
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = "#071014";
  context.fillRect(0, 0, canvas.width, 80);
  context.fillStyle = "#b8f36b";
  context.font = "700 28px sans-serif";
  context.fillText("NORTHSTAR CHECKOUT", 56, 50);
  context.fillStyle = "#ffffff";
  context.fillRect(150, 130, 980, 470);
  context.fillStyle = "#071014";
  context.font = "700 42px sans-serif";
  context.fillText("Payment failed", 230, 210);
  context.fillStyle = "#59655f";
  context.font = "24px sans-serif";
  context.fillText("Account: alice@example.com", 230, 285);
  context.fillText("Session: sess_live_4f9c2a7b", 230, 340);
  context.fillStyle = "#9d2d28";
  context.font = "600 24px monospace";
  context.fillText("POST /v1/orders — 500 Internal Server Error", 230, 440);
  context.fillStyle = "#071014";
  context.font = "18px sans-serif";
  context.fillText("Reference: ch_8N2Q • Try again or contact support", 230, 505);
  const blob = await new Promise<Blob>((resolve, reject) =>
    canvas.toBlob((value) => value ? resolve(value) : reject(new Error("Could not create demo image.")), "image/png"),
  );
  return new File([blob], "checkout-error.png", { type: "image/png" });
}

export default function Home() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [step, setStep] = useState<Step>("import");
  const [files, setFiles] = useState<FileSet>({});
  const [result, setResult] = useState<ScanResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState("");
  const [customTerms, setCustomTerms] = useState<string[]>([]);
  const [customInput, setCustomInput] = useState("");
  const [maskedScreenshot, setMaskedScreenshot] = useState<Blob | null>(null);
  const [maskCount, setMaskCount] = useState(0);
  const [confirmed, setConfirmed] = useState(false);
  const [lastDownload, setLastDownload] = useState<{ blob: Blob; name: string; size: number } | null>(null);

  const scanFileSet = useCallback(async (nextFiles: FileSet, terms: string[]) => {
    setBusy(true);
    setError("");
    try {
      const [harText, consoleText] = await Promise.all([
        nextFiles.har?.text(),
        nextFiles.console?.text(),
      ]);
      await new Promise((resolve) => window.setTimeout(resolve, 180));
      const nextResult = scanDiagnostics({ harText, consoleText, customTerms: terms });
      setResult(nextResult);
      setConfirmed(false);
      setLastDownload(null);
      setStep("review");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The files could not be scanned.");
    } finally {
      setBusy(false);
    }
  }, []);

  const loadDemo = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const screenshot = await demoScreenshot();
      const nextFiles: FileSet = {
        har: new File([demoHar], "session.har", { type: "application/json" }),
        console: new File([demoConsole], "console.json", { type: "application/json" }),
        screenshot,
      };
      setFiles(nextFiles);
      setCustomTerms([]);
      setMaskedScreenshot(null);
      await scanFileSet(nextFiles, []);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The demo could not be prepared.");
      setBusy(false);
    }
  }, [scanFileSet]);

  useEffect(() => {
    const context = document.modelContext;
    if (!context?.registerTool) return;
    const lifecycle = new AbortController();
    try {
      void Promise.resolve(context.registerTool({
        name: "load_demo_parcel",
        title: "Load demo parcel",
        description: "Load the built-in safe HAR, console log, and screenshot demo into DebugParcel and run a local scan.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false },
        annotations: { readOnlyHint: false, untrustedContentHint: false },
        async execute(input) {
          if (
            !input ||
            typeof input !== "object" ||
            Array.isArray(input) ||
            Object.keys(input as Record<string, unknown>).length > 0
          ) {
            throw new Error("load_demo_parcel accepts an empty object only.");
          }
          await loadDemo();
          return { status: "ready", view: "review" };
        },
      }, { signal: lifecycle.signal })).catch(() => undefined);
    } catch {
      // WebMCP is optional and unsupported browsers keep the normal UI.
    }
    return () => lifecycle.abort();
  }, [loadDemo]);

  const processFiles = (incoming: FileList | File[]) => {
    const next = { ...files };
    let nextError = "";
    for (const file of Array.from(incoming)) {
      const kind = detectKind(file);
      if (!kind) {
        nextError = `${file.name} is not a supported file type.`;
        continue;
      }
      const limit = kind === "screenshot" ? 12 * 1024 ** 2 : 50 * 1024 ** 2;
      if (file.size > limit) {
        nextError = `${file.name} exceeds the ${kind === "screenshot" ? "12" : "50"} MB limit.`;
        continue;
      }
      next[kind] = file;
    }
    setFiles(next);
    setResult(null);
    setLastDownload(null);
    setMaskedScreenshot(null);
    setError(nextError);
  };

  const removeFile = (kind: FileKind) => {
    const next = { ...files };
    delete next[kind];
    setFiles(next);
    setResult(null);
    setLastDownload(null);
    if (kind === "screenshot") setMaskedScreenshot(null);
  };

  const addCustomTerm = async () => {
    const term = customInput.trim();
    if (!term || customTerms.includes(term)) return;
    const nextTerms = [...customTerms, term];
    setCustomTerms(nextTerms);
    setCustomInput("");
    await scanFileSet(files, nextTerms);
  };

  const categories = useMemo(
    () => result ? findingsByCategory(result.findings) : {},
    [result],
  );
  const occurrenceCount = result?.findings.reduce((sum, finding) => sum + finding.occurrences, 0) ?? 0;
  const fileCount = Object.keys(files).length;
  const currentIndex = steps.findIndex((item) => item.id === step);

  const buildReport = (scan: ScanResult) => {
    const failed = scan.requests.filter((request) => request.status >= 400);
    const categoryLines = Object.entries(findingsByCategory(scan.findings))
      .map(([category, counts]) => `- ${findingLabel(category as Finding["category"])}: ${counts.entities} unique, ${counts.occurrences} occurrence(s)`)
      .join("\n") || "- No automatic matches";
    const requestLines = failed
      .map((request) => `- \`${request.method} ${request.target}\` → **${request.status}**${request.duration !== null ? ` in ${request.duration} ms` : ""}`)
      .join("\n") || "- No HTTP 4xx/5xx requests found";
    return `# Debug report

Generated locally by DebugParcel. Review this report together with the attached sanitized evidence.

## Failure summary

${requestLines}

## Privacy summary

- ${scan.findings.length} unique sensitive values replaced across ${occurrenceCount} location(s)
- ${scan.omittedBodies} request/response body value(s) omitted by default
- Privacy audit: ${scan.auditPassed ? "passed" : "blocked"}

${categoryLines}

## Included evidence

${scan.sanitizedHar ? "- `network.sanitized.har`" : ""}
${scan.sanitizedConsole ? "- `console.sanitized.json`" : ""}
${files.screenshot ? "- `screenshot.redacted.png`" : ""}

> Automatic redaction cannot guarantee that every sensitive value was detected. The reporter reviewed the sanitized preview before exporting.
`;
  };

  const exportParcel = async () => {
    if (!result || !confirmed || !result.auditPassed) return;
    if (files.screenshot && !maskedScreenshot) {
      setError("The screenshot is still being prepared. Wait a moment and try again.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const payloads: Array<{ name: string; data: Blob | string }> = [];
      if (result.sanitizedHar) payloads.push({ name: "network.sanitized.har", data: result.sanitizedHar });
      if (result.sanitizedConsole) payloads.push({ name: "console.sanitized.json", data: result.sanitizedConsole });
      if (maskedScreenshot) payloads.push({ name: "screenshot.redacted.png", data: maskedScreenshot });
      const report = buildReport(result);
      payloads.unshift({ name: "report.md", data: report });

      const checksums = await Promise.all(
        payloads.map(async (item) => ({ name: item.name, sha256: await sha256(item.data) })),
      );
      const manifest = JSON.stringify({
        schemaVersion: 1,
        tool: { name: "DebugParcel", version: "0.1.0" },
        createdAt: new Date().toISOString(),
        privacy: {
          auditPassed: true,
          uniqueEntities: result.findings.length,
          occurrences: occurrenceCount,
          omittedBodies: result.omittedBodies,
          screenshotMasks: maskCount,
          categories,
        },
        files: checksums,
      }, null, 2);
      const zip = await makeZip([...payloads, { name: "manifest.json", data: manifest }]);
      const name = `debugparcel-${dateSlug()}.zip`;
      downloadBlob(zip, name);
      setLastDownload({ blob: zip, name, size: zip.size });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The parcel could not be exported.");
    } finally {
      setBusy(false);
    }
  };

  const handleMaskedChange = useCallback((blob: Blob | null) => setMaskedScreenshot(blob), []);
  const handleMaskCount = useCallback((count: number) => setMaskCount(count), []);

  return (
    <main className="min-h-screen bg-[var(--background)] text-[var(--foreground)]">
      <header className="border-b border-white/10 bg-[var(--ink)] text-white">
        <div className="mx-auto flex h-16 max-w-[1440px] items-center justify-between px-5 lg:px-10">
          <button
            type="button"
            onClick={() => setStep("import")}
            className="flex items-center gap-3 rounded-xl text-left"
            aria-label="DebugParcel home"
          >
            <span className="grid size-9 place-items-center rounded-xl bg-[var(--signal)] text-[var(--ink)]">
              <Archive size={19} strokeWidth={2.4} />
            </span>
            <span>
              <span className="block font-display text-lg font-semibold leading-none tracking-[-0.03em]">DebugParcel</span>
              <span className="mt-1 block font-mono text-[11px] uppercase tracking-[0.16em] text-white/45">Private debug bundles</span>
            </span>
          </button>
          <div className="flex items-center gap-2 rounded-full border border-white/15 bg-white/[0.06] px-3 py-1.5 font-mono text-xs text-white/75">
            <LockKeyhole size={13} className="text-[var(--signal)]" />
            <span className="hidden sm:inline">Runs on this device</span>
            <span className="sm:hidden">Local only</span>
          </div>
        </div>
      </header>

      <div className="mx-auto grid max-w-[1440px] gap-8 px-5 py-7 lg:grid-cols-[minmax(0,1fr)_330px] lg:px-10 lg:py-9">
        <div className="min-w-0">
          {error && (
            <div role="alert" className="mb-5 flex items-start gap-3 rounded-2xl border border-[#e0a6a1] bg-[#fff1ef] p-4 text-sm text-[#7c2520]">
              <CircleAlert className="mt-0.5 shrink-0" size={18} />
              <span className="flex-1">{error}</span>
              <button type="button" onClick={() => setError("")} aria-label="Dismiss error"><X size={17} /></button>
            </div>
          )}

          {step === "import" && (
            <>
              <div className="mb-7 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
                <div>
                  <p className="eyebrow">New parcel</p>
                  <h1 className="mt-2 max-w-3xl font-display text-[clamp(2rem,4vw,4rem)] font-semibold leading-[0.95] tracking-[-0.055em]">
                    Share the bug.<br />
                    <span className="text-[var(--muted-strong)]">Keep the secrets.</span>
                  </h1>
                </div>
                <div className="flex items-center gap-2 text-sm text-[var(--muted-strong)]">
                  <ShieldCheck size={17} /> Nothing is uploaded
                </div>
              </div>

              <section className="work-card overflow-hidden" aria-labelledby="import-heading">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--line)] px-5 py-4 sm:px-6">
                  <div>
                    <p className="eyebrow">01 / Import</p>
                    <h2 id="import-heading" className="mt-1 font-display text-xl font-semibold tracking-tight">Add diagnostic files</h2>
                  </div>
                  <button type="button" className="secondary-button" onClick={() => void loadDemo()} disabled={busy}>
                    <Sparkles size={15} /> Try safe demo
                  </button>
                </div>

                <input
                  ref={inputRef}
                  className="sr-only"
                  type="file"
                  multiple
                  accept=".har,.json,.txt,.log,.png,.jpg,.jpeg,.webp,application/json,text/plain,image/*"
                  onChange={(event) => event.target.files && processFiles(event.target.files)}
                />
                <button
                  type="button"
                  className={`upload-zone group mx-5 my-5 w-[calc(100%-2.5rem)] sm:mx-6 sm:my-6 sm:w-[calc(100%-3rem)] ${dragging ? "is-dragging" : ""}`}
                  onClick={() => inputRef.current?.click()}
                  onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
                  onDragOver={(event) => event.preventDefault()}
                  onDragLeave={() => setDragging(false)}
                  onDrop={(event) => {
                    event.preventDefault();
                    setDragging(false);
                    processFiles(event.dataTransfer.files);
                  }}
                >
                  <span className="grid size-12 place-items-center rounded-2xl border border-[var(--line)] bg-white shadow-sm transition-transform group-hover:-translate-y-0.5">
                    <UploadCloud size={22} />
                  </span>
                  <span className="mt-4 font-display text-lg font-semibold">
                    {dragging ? "Release to add files" : "Drop files here or choose from device"}
                  </span>
                  <span className="mt-1 text-sm text-[var(--muted-strong)]">Add any combination of HAR, console log, and screenshot</span>
                </button>

                <div className="grid border-t border-[var(--line)] sm:grid-cols-3">
                  {(Object.keys(fileMeta) as FileKind[]).map((kind) => {
                    const meta = fileMeta[kind];
                    const Icon = meta.icon;
                    const file = files[kind];
                    return (
                      <div key={kind} className="min-w-0 border-b border-[var(--line)] px-5 py-4 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0">
                        <div className="flex items-center gap-3">
                          <span className={`grid size-9 shrink-0 place-items-center rounded-xl ${file ? "bg-[var(--signal)]" : "bg-[var(--soft)]"}`}>
                            {file ? <Check size={17} strokeWidth={3} /> : <Icon size={17} />}
                          </span>
                          <div className="min-w-0 flex-1">
                            <p className="text-sm font-semibold">{meta.label}</p>
                            <p className="truncate font-mono text-[11px] text-[var(--muted-strong)]">
                              {file ? `${file.name} · ${formatBytes(file.size)}` : meta.hint}
                            </p>
                          </div>
                          {file && (
                            <button type="button" onClick={() => removeFile(kind)} className="icon-button" aria-label={`Remove ${meta.label}`}>
                              <Trash2 size={15} />
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>

              <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className="max-w-xl text-sm leading-6 text-[var(--muted-strong)]">
                  Request and response bodies are omitted by default. Originals remain in memory only until this tab closes.
                </p>
                <button
                  type="button"
                  className="primary-button"
                  onClick={() => void scanFileSet(files, customTerms)}
                  disabled={!fileCount || busy}
                >
                  {busy ? "Scanning locally…" : "Scan files"} <ArrowRight size={17} />
                </button>
              </div>
              {busy && <Progress value={62} className="mt-4 bg-[var(--soft)] [&>div]:bg-[var(--ink)]" aria-label="Scanning files" />}
            </>
          )}

          {step === "review" && result && (
            <section aria-labelledby="review-heading">
              <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
                <div>
                  <p className="eyebrow">02 / Review</p>
                  <h1 id="review-heading" className="mt-2 font-display text-4xl font-semibold tracking-[-0.05em]">Privacy findings</h1>
                  <p className="mt-2 text-[var(--muted-strong)]">
                    {result.findings.length} unique values replaced across {occurrenceCount} locations.
                  </p>
                </div>
                <span className={`inline-flex w-fit items-center gap-2 rounded-full px-3 py-1.5 text-sm font-semibold ${result.auditPassed ? "bg-[#e0f7ca] text-[#21430d]" : "bg-[#fff1ef] text-[#7c2520]"}`}>
                  {result.auditPassed ? <CheckCircle2 size={16} /> : <CircleAlert size={16} />}
                  {result.auditPassed ? "Leak audit passed" : "Export blocked"}
                </span>
              </div>

              <div className="risk-note mb-5">
                <CircleAlert size={18} />
                <p><strong>Automatic redaction can miss sensitive data.</strong> Review URLs, logs, and the screenshot before export. Files never leave this browser.</p>
              </div>

              <div className="mb-5 grid gap-3 sm:grid-cols-3">
                <Stat label="Unique entities" value={String(result.findings.length)} />
                <Stat label="Replaced locations" value={String(occurrenceCount)} />
                <Stat label="Bodies omitted" value={String(result.omittedBodies)} />
              </div>

              <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(320px,.8fr)]">
                <section className="work-card overflow-hidden">
                  <div className="border-b border-[var(--line)] px-5 py-4">
                    <p className="eyebrow">Detected values</p>
                    <h2 className="mt-1 font-display text-xl font-semibold">Consistent aliases</h2>
                  </div>
                  <div className="max-h-[540px] overflow-y-auto">
                    {result.findings.length ? result.findings.map((finding) => (
                      <FindingRow key={finding.id} finding={finding} />
                    )) : (
                      <div className="p-7 text-sm leading-6 text-[var(--muted-strong)]">
                        The automatic scan found no matching values. This is not a guarantee of safety; continue with a manual review.
                      </div>
                    )}
                  </div>
                </section>

                <section className="work-card overflow-hidden">
                  <div className="border-b border-[var(--line)] px-5 py-4">
                    <p className="eyebrow">Sanitized preview</p>
                    <h2 className="mt-1 font-display text-xl font-semibold">Safe output only</h2>
                  </div>
                  <pre className="preview-code max-h-[390px] overflow-auto p-5" tabIndex={0}>
                    {(result.sanitizedConsole || result.sanitizedHar || "No text evidence supplied.").slice(0, 12000)}
                  </pre>
                  <div className="border-t border-[var(--line)] p-5">
                    <label className="mb-2 block text-sm font-semibold" htmlFor="custom-redaction">Add a value the scan missed</label>
                    <div className="flex gap-2">
                      <input
                        id="custom-redaction"
                        type="password"
                        value={customInput}
                        onChange={(event) => setCustomInput(event.target.value)}
                        onKeyDown={(event) => { if (event.key === "Enter") void addCustomTerm(); }}
                        className="text-input min-w-0 flex-1"
                        placeholder="Exact value to redact"
                      />
                      <button type="button" className="secondary-button shrink-0" onClick={() => void addCustomTerm()} disabled={!customInput.trim() || busy}>
                        <Plus size={15} /> Add
                      </button>
                    </div>
                    <p className="mt-2 text-xs leading-5 text-[var(--muted-strong)]">The value stays in memory and is never written to the ZIP.</p>
                  </div>
                </section>
              </div>

              <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-between">
                <button type="button" className="secondary-button" onClick={() => setStep("import")}>
                  <ArrowLeft size={17} /> Back to files
                </button>
                <button type="button" className="primary-button" onClick={() => setStep(files.screenshot ? "mask" : "export")} disabled={!result.auditPassed}>
                  {files.screenshot ? "Review screenshot" : "Prepare export"} <ArrowRight size={17} />
                </button>
              </div>
            </section>
          )}

          {step === "mask" && files.screenshot && result && (
            <section aria-labelledby="mask-heading">
              <div className="mb-6">
                <p className="eyebrow">03 / Mask</p>
                <h1 id="mask-heading" className="mt-2 font-display text-4xl font-semibold tracking-[-0.05em]">Burn in screenshot masks</h1>
                <p className="mt-2 max-w-2xl text-[var(--muted-strong)]">Drag to cover sensitive regions. Select a mask to move it; use Shift plus arrow keys to resize.</p>
              </div>
              <section className="work-card p-4 sm:p-5">
                <ScreenshotRedactor
                  key={`${files.screenshot.name}-${files.screenshot.lastModified}`}
                  file={files.screenshot}
                  onChange={handleMaskedChange}
                  onMaskCount={handleMaskCount}
                />
              </section>
              <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-between">
                <button type="button" className="secondary-button" onClick={() => setStep("review")}>
                  <ArrowLeft size={17} /> Back to findings
                </button>
                <button type="button" className="primary-button" onClick={() => setStep("export")} disabled={!maskedScreenshot}>
                  Prepare export <ArrowRight size={17} />
                </button>
              </div>
            </section>
          )}

          {step === "export" && result && (
            <section aria-labelledby="export-heading">
              <div className="mb-6">
                <p className="eyebrow">04 / Export</p>
                <h1 id="export-heading" className="mt-2 font-display text-4xl font-semibold tracking-[-0.05em]">Seal the parcel</h1>
                <p className="mt-2 text-[var(--muted-strong)]">One issue-ready ZIP, with originals excluded.</p>
              </div>

              <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
                <section className="work-card overflow-hidden">
                  <div className="border-b border-[var(--line)] px-5 py-4 sm:px-6">
                    <p className="eyebrow">Package contents</p>
                    <h2 className="mt-1 font-display text-xl font-semibold">Only sanitized evidence</h2>
                  </div>
                  <div className="divide-y divide-[var(--line)]">
                    <PackageRow name="report.md" detail="Issue-ready failure and privacy summary" />
                    {result.sanitizedHar && <PackageRow name="network.sanitized.har" detail="Network timeline with bodies omitted" />}
                    {result.sanitizedConsole && <PackageRow name="console.sanitized.json" detail="Console output with consistent aliases" />}
                    {files.screenshot && <PackageRow name="screenshot.redacted.png" detail={`${maskCount} permanent pixel mask${maskCount === 1 ? "" : "s"}`} />}
                    <PackageRow name="manifest.json" detail="Checksums and non-sensitive scan totals" />
                  </div>
                </section>

                <section className="rounded-[24px] bg-[var(--ink)] p-6 text-white shadow-[0_24px_70px_rgba(2,14,18,.14)]">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-white/45">Final check</p>
                      <h2 className="mt-2 font-display text-2xl font-semibold tracking-[-0.035em]">Ready to export</h2>
                    </div>
                    <span className="grid size-10 place-items-center rounded-full bg-[var(--signal)] text-[var(--ink)]">
                      <ShieldCheck size={20} />
                    </span>
                  </div>
                  <div className="mt-5 space-y-3 border-y border-white/10 py-5 text-sm text-white/76">
                    <p className="flex items-center gap-2"><Check size={15} className="text-[var(--signal)]" /> Text leak audit passed</p>
                    <p className="flex items-center gap-2"><Check size={15} className="text-[var(--signal)]" /> Original bodies excluded</p>
                    <p className="flex items-center gap-2"><Check size={15} className="text-[var(--signal)]" /> No reverse alias map</p>
                  </div>
                  <label className="mt-5 flex cursor-pointer items-start gap-3 text-sm leading-6 text-white/80">
                    <Checkbox
                      checked={confirmed}
                      onCheckedChange={(checked) => setConfirmed(checked === true)}
                      className="mt-1 border-white/35 data-[state=checked]:border-[var(--signal)] data-[state=checked]:bg-[var(--signal)] data-[state=checked]:text-[var(--ink)]"
                    />
                    <span>I reviewed the sanitized preview and understand that automated detection may miss sensitive information.</span>
                  </label>
                  <button type="button" className="export-button mt-5 w-full" onClick={() => void exportParcel()} disabled={!confirmed || busy || !result.auditPassed}>
                    <Download size={17} /> {busy ? "Building parcel…" : "Download ZIP"}
                  </button>
                  {lastDownload && (
                    <div className="mt-4 rounded-xl bg-white/[0.07] p-3 text-sm">
                      <p className="font-semibold text-[var(--signal)]">Parcel downloaded</p>
                      <p className="mt-1 truncate font-mono text-[11px] text-white/55">{lastDownload.name} · {formatBytes(lastDownload.size)}</p>
                      <button type="button" className="mt-2 text-sm font-semibold underline decoration-white/30 underline-offset-4" onClick={() => downloadBlob(lastDownload.blob, lastDownload.name)}>
                        Download again
                      </button>
                    </div>
                  )}
                </section>
              </div>

              <div className="mt-6 flex">
                <button type="button" className="secondary-button" onClick={() => setStep(files.screenshot ? "mask" : "review")}>
                  <ArrowLeft size={17} /> Back to review
                </button>
              </div>
            </section>
          )}
        </div>

        <aside className="space-y-5 lg:sticky lg:top-6 lg:self-start">
          <section className="rounded-[24px] bg-[var(--ink)] p-6 text-white shadow-[0_24px_70px_rgba(2,14,18,.14)]">
            <div className="flex items-start justify-between">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-white/45">Privacy seal</p>
                <h2 className="mt-2 font-display text-2xl font-semibold tracking-[-0.035em]">Local by design</h2>
              </div>
              <span className="grid size-10 place-items-center rounded-full bg-[var(--signal)] text-[var(--ink)]"><ShieldCheck size={20} /></span>
            </div>
            <p className="mt-4 text-sm leading-6 text-white/62">Parsing, masking, hashing, and ZIP creation all happen inside this tab.</p>
            <div className="mt-6 grid gap-3 border-t border-white/10 pt-5">
              {["No account", "No cloud processing", "Review before export"].map((item) => (
                <div key={item} className="flex items-center gap-2 text-sm text-white/78">
                  <span className="grid size-5 place-items-center rounded-full bg-white/10 text-[var(--signal)]"><Check size={12} strokeWidth={3} /></span>
                  {item}
                </div>
              ))}
            </div>
          </section>

          <nav className="work-card p-5" aria-label="Parcel progress">
            <p className="eyebrow">Parcel progress</p>
            <ol className="mt-4 space-y-1">
              {steps.map((item, index) => {
                const complete = index < currentIndex;
                const active = item.id === step;
                const canVisit = index <= currentIndex && (item.id === "import" || !!result);
                return (
                  <li key={item.id}>
                    <button
                      type="button"
                      disabled={!canVisit}
                      onClick={() => canVisit && setStep(item.id)}
                      className={`flex w-full items-center gap-3 rounded-xl px-2 py-2.5 text-left text-sm transition-colors ${active ? "bg-[var(--soft)]" : canVisit ? "hover:bg-[var(--soft)]" : ""}`}
                    >
                      <span className={`grid size-7 place-items-center rounded-full font-mono text-xs ${active ? "bg-[var(--ink)] text-white" : complete ? "bg-[var(--signal)] text-[var(--ink)]" : "bg-[var(--soft)] text-[var(--muted-strong)]"}`}>
                        {complete ? <Check size={13} strokeWidth={3} /> : index + 1}
                      </span>
                      <span className={active ? "font-semibold" : complete ? "text-[var(--foreground)]" : "text-[var(--muted-strong)]"}>{item.label}</span>
                    </button>
                  </li>
                );
              })}
            </ol>
          </nav>
        </aside>
      </div>
      <div className="sr-only" aria-live="polite">{busy ? "Processing files locally" : lastDownload ? "Parcel export complete" : ""}</div>
    </main>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="work-card px-5 py-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-[var(--muted-strong)]">{label}</p>
      <p className="mt-1 font-display text-3xl font-semibold tracking-[-0.04em]">{value}</p>
    </div>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 last:border-b-0 sm:grid-cols-[145px_minmax(0,1fr)_auto] sm:items-center">
      <div>
        <span className="category-pill">{findingLabel(finding.category)}</span>
      </div>
      <div className="min-w-0">
        <p className="truncate font-mono text-sm font-semibold">{finding.alias}</p>
        <p className="mt-1 truncate text-xs text-[var(--muted-strong)]">{finding.maskedSample} · {finding.locations[0]}</p>
      </div>
      <span className="font-mono text-xs text-[var(--muted-strong)]">{finding.occurrences}×</span>
    </div>
  );
}

function PackageRow({ name, detail }: { name: string; detail: string }) {
  return (
    <div className="flex items-center gap-4 px-5 py-4 sm:px-6">
      <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-[var(--signal)]"><Check size={16} strokeWidth={3} /></span>
      <div className="min-w-0">
        <p className="truncate font-mono text-sm font-semibold">{name}</p>
        <p className="mt-1 text-sm text-[var(--muted-strong)]">{detail}</p>
      </div>
    </div>
  );
}
