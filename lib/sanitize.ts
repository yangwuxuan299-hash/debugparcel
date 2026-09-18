export type FindingCategory =
  | "AUTH"
  | "API_KEY"
  | "COOKIE"
  | "EMAIL"
  | "HOST"
  | "IP"
  | "PATH"
  | "PRIVATE_KEY"
  | "QUERY"
  | "SECRET"
  | "SESSION"
  | "USER_ID";

export type Finding = {
  id: string;
  category: FindingCategory;
  alias: string;
  occurrences: number;
  locations: string[];
  maskedSample: string;
  raw: string;
};

export type RequestSummary = {
  method: string;
  target: string;
  status: number;
  duration: number | null;
};

export type ScanResult = {
  sanitizedHar?: string;
  sanitizedConsole?: string;
  findings: Finding[];
  omittedBodies: number;
  requests: RequestSummary[];
  auditPassed: boolean;
  auditMessage: string;
};

type RegistryEntry = Finding & { canonical: string };

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "api-key",
  "x-auth-token",
  "x-access-token",
  "x-csrf-token",
  "x-xsrf-token",
  "private-token",
  "x-goog-api-key",
]);

const SENSITIVE_KEYS = new Set([
  "authorization",
  "proxyauthorization",
  "cookie",
  "setcookie",
  "password",
  "passwd",
  "pwd",
  "secret",
  "clientsecret",
  "apikey",
  "accesskey",
  "token",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "session",
  "sessionid",
  "csrf",
  "xsrf",
  "credential",
  "privatekey",
]);

const OMITTED_REQUEST_BODY = "[REQUEST_BODY_OMITTED]";
const OMITTED_RESPONSE_BODY = "[RESPONSE_BODY_OMITTED]";

function normalizeKey(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isSensitiveKey(value: string) {
  const key = normalizeKey(value);
  return (
    SENSITIVE_KEYS.has(key) ||
    ["token", "secret", "password", "passwd", "apikey", "cookie", "credential"].some(
      (suffix) => key.endsWith(suffix),
    )
  );
}

function canonicalize(category: FindingCategory, value: string) {
  const trimmed = value.trim().replace(/^["']|["']$/g, "");
  if (category === "EMAIL" || category === "HOST") return trimmed.toLowerCase();
  if (category === "IP") {
    const octets = trimmed.split(".");
    if (octets.length === 4 && octets.every((part) => /^\d{1,3}$/.test(part))) {
      return octets.map((part) => String(Number(part))).join(".");
    }
  }
  return trimmed;
}

function maskedSample(category: FindingCategory, raw: string) {
  if (category === "EMAIL") {
    const [name, domain] = raw.split("@");
    return `${name?.slice(0, 1) || "•"}•••@${domain || "•••"}`;
  }
  if (category === "IP") {
    const parts = raw.split(".");
    return parts.length === 4 ? `${parts[0]}.•••.•••.${parts[3]}` : "••••";
  }
  if (category === "PATH") {
    const slash = raw.includes("\\") ? "\\" : "/";
    const tail = raw.split(/[\\/]/).filter(Boolean).pop();
    return `${slash}•••/${tail || "path"}`;
  }
  if (raw.length <= 7) return "••••";
  return `${raw.slice(0, 3)}••••${raw.slice(-2)}`;
}

class Registry {
  private entries = new Map<string, RegistryEntry>();
  private counters = new Map<FindingCategory, number>();

  alias(category: FindingCategory, raw: string, location: string) {
    const canonical = canonicalize(category, raw);
    const key = `${category}:\0${canonical}`;
    const existing = this.entries.get(key);
    if (existing) {
      existing.occurrences += 1;
      if (!existing.locations.includes(location) && existing.locations.length < 4) {
        existing.locations.push(location);
      }
      return existing.alias;
    }

    const count = (this.counters.get(category) ?? 0) + 1;
    this.counters.set(category, count);
    const alias = `[${category}_${count}]`;
    const entry: RegistryEntry = {
      id: `${category.toLowerCase()}-${count}`,
      category,
      alias,
      occurrences: 1,
      locations: [location],
      maskedSample: maskedSample(category, raw),
      raw,
      canonical,
    };
    this.entries.set(key, entry);
    return alias;
  }

  values() {
    return [...this.entries.values()];
  }
}

function validIpv4(candidate: string) {
  const parts = candidate.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function replaceWith(
  input: string,
  pattern: RegExp,
  category: FindingCategory,
  registry: Registry,
  location: string,
) {
  return input.replace(pattern, (match) => registry.alias(category, match, location));
}

function sanitizeCookieHeader(
  input: string,
  registry: Registry,
  location: string,
  setCookie = false,
) {
  return input
    .split(";")
    .map((part, index) => {
      const trimmed = part.trim();
      const equals = trimmed.indexOf("=");
      if (equals < 0) return trimmed;
      const name = trimmed.slice(0, equals);
      const value = trimmed.slice(equals + 1);
      if (
        setCookie &&
        index > 0 &&
        ["expires", "max-age", "samesite"].includes(name.toLowerCase())
      ) {
        return trimmed;
      }
      const category: FindingCategory = name.toLowerCase() === "session" ? "SESSION" : "COOKIE";
      return `${name}=${registry.alias(category, value, location)}`;
    })
    .join("; ");
}

function sanitizeAuthHeader(input: string, registry: Registry, location: string) {
  const match = input.match(/^\s*(Bearer|Basic)\s+(.+)$/i);
  if (!match) return registry.alias("AUTH", input, location);
  return `${match[1]} ${registry.alias("AUTH", match[2], location)}`;
}

function sanitizeString(input: string, registry: Registry, location: string) {
  if (
    input === OMITTED_REQUEST_BODY ||
    input === OMITTED_RESPONSE_BODY ||
    /^\[[A-Z_]+_\d+\]$/.test(input)
  ) {
    return input;
  }

  let output = input
    .replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\x1B\][^\x07]*(?:\x07|\x1B\\)/g, "");

  output = replaceWith(
    output,
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{1,100000}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    "PRIVATE_KEY",
    registry,
    location,
  );

  output = output.replace(
    /\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{8,})/gi,
    (_, scheme: string, token: string) =>
      `${scheme} ${registry.alias("AUTH", token, location)}`,
  );
  output = replaceWith(
    output,
    /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
    "AUTH",
    registry,
    location,
  );
  output = replaceWith(
    output,
    /\b(?:github_pat_[A-Za-z0-9_]{20,255}|gh[pousr]_[A-Za-z0-9]{20,255}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b/g,
    "API_KEY",
    registry,
    location,
  );

  output = output.replace(
    /[A-Z0-9._%+-]{1,64}%40[A-Z0-9-]+(?:\.[A-Z0-9-]+)+/gi,
    (encoded) => {
      let decoded = encoded;
      try {
        decoded = decodeURIComponent(encoded);
      } catch {
        // Keep the original candidate if it cannot be decoded.
      }
      return encodeURIComponent(registry.alias("EMAIL", decoded, location));
    },
  );
  output = replaceWith(
    output,
    /[A-Z0-9._%+-]{1,64}@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+/gi,
    "EMAIL",
    registry,
    location,
  );

  output = output.replace(
    /\b(api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|pwd)\b(\s*[:=]\s*)(["']?)(\[[A-Z_]+_\d+\]|[^\s,;&\]}]+)\3/gi,
    (whole, key: string, separator: string, quote: string, value: string) =>
      /^\[[A-Z_]+_\d+\]$/.test(value)
        ? whole
        : `${key}${separator}${quote}${registry.alias("SECRET", value, location)}${quote}`,
  );
  output = replaceWith(
    output,
    /\bsess_(?:live|test)?_?[A-Za-z0-9]{6,}\b/gi,
    "SESSION",
    registry,
    location,
  );
  output = replaceWith(output, /\busr_[A-Za-z0-9_-]{2,}\b/g, "USER_ID", registry, location);
  output = replaceWith(
    output,
    /(?:\/Users|\/home)\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._ -]+){1,}/g,
    "PATH",
    registry,
    location,
  );
  output = replaceWith(
    output,
    /\b(?:[A-Za-z0-9-]+\.)+(?:internal|local)\b/gi,
    "HOST",
    registry,
    location,
  );
  output = output.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (candidate) =>
    validIpv4(candidate) ? registry.alias("IP", candidate, location) : candidate,
  );

  output = output.replace(
    /([?&])([^=&#\s]+)=([^&#\s]*)/g,
    (whole, prefix: string, key: string, value: string) => {
      if (!value) return whole;
      let decoded = value;
      try {
        decoded = decodeURIComponent(value);
      } catch {
        // Preserve malformed URL values as candidates.
      }
      if (/^\[[A-Z_]+_\d+\]$/.test(decoded)) return whole;
      const category: FindingCategory = isSensitiveKey(key) ? "SECRET" : "QUERY";
      return `${prefix}${key}=${encodeURIComponent(registry.alias(category, decoded, location))}`;
    },
  );

  return output;
}

function cloneValue<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function sanitizeNode(
  value: unknown,
  registry: Registry,
  path: string,
  depth = 0,
): unknown {
  if (depth > 64) throw new Error("Input nesting is too deep to process safely.");
  if (Array.isArray(value)) {
    return value.map((item, index) => sanitizeNode(item, registry, `${path}[${index}]`, depth + 1));
  }
  if (!value || typeof value !== "object") {
    return typeof value === "string" ? sanitizeString(value, registry, path) : value;
  }

  const source = value as Record<string, unknown>;
  const output: Record<string, unknown> = {};
  const headerName = typeof source.name === "string" ? source.name.toLowerCase() : "";
  for (const [key, child] of Object.entries(source)) {
    const childPath = path ? `${path}.${key}` : key;
    if (
      key === "value" &&
      typeof child === "string" &&
      SENSITIVE_HEADERS.has(headerName)
    ) {
      if (headerName === "authorization" || headerName === "proxy-authorization") {
        output[key] = sanitizeAuthHeader(child, registry, childPath);
      } else if (headerName === "cookie") {
        output[key] = sanitizeCookieHeader(child, registry, childPath);
      } else if (headerName === "set-cookie") {
        output[key] = sanitizeCookieHeader(child, registry, childPath, true);
      } else {
        output[key] = registry.alias("SECRET", child, childPath);
      }
    } else if (isSensitiveKey(key) && (typeof child !== "object" || child === null)) {
      output[key] =
        typeof child === "string"
          ? registry.alias("SECRET", child, childPath)
          : registry.alias("SECRET", JSON.stringify(child), childPath);
    } else if (isSensitiveKey(key) && child && typeof child === "object") {
      output[key] = registry.alias("SECRET", JSON.stringify(child), childPath);
    } else {
      output[key] = sanitizeNode(child, registry, childPath, depth + 1);
    }
  }
  return output;
}

function audit(outputs: string[], findings: RegistryEntry[]) {
  for (const finding of findings) {
    const variants = [finding.raw];
    try {
      variants.push(encodeURIComponent(finding.raw));
    } catch {
      // Ignore values that cannot be URI encoded.
    }
    if (outputs.some((output) => variants.some((variant) => variant && output.includes(variant)))) {
      return {
        passed: false,
        message: `A ${finding.category.toLowerCase()} value survived the privacy audit.`,
      };
    }
  }
  const joined = outputs.join("\n");
  if (
    /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/.test(joined) ||
    /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/i.test(joined)
  ) {
    return { passed: false, message: "A high-confidence credential survived the privacy audit." };
  }
  return { passed: true, message: "No known source value remains in the sanitized text files." };
}

export function scanDiagnostics({
  harText,
  consoleText,
  customTerms = [],
}: {
  harText?: string;
  consoleText?: string;
  customTerms?: string[];
}): ScanResult {
  const registry = new Registry();
  let sanitizedHar: string | undefined;
  let sanitizedConsole: string | undefined;
  let omittedBodies = 0;
  const requests: RequestSummary[] = [];

  if (harText) {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(harText) as Record<string, unknown>;
    } catch {
      throw new Error("The HAR file is not valid JSON.");
    }
    const cloned = cloneValue(parsed);
    const entries =
      ((cloned.log as Record<string, unknown> | undefined)?.entries as Array<Record<string, unknown>> | undefined) ?? [];

    for (const entry of entries) {
      const request = entry.request as Record<string, unknown> | undefined;
      const response = entry.response as Record<string, unknown> | undefined;
      const url = typeof request?.url === "string" ? request.url : "";
      let target = url;
      try {
        const parsedUrl = new URL(url);
        target = parsedUrl.pathname || "/";
      } catch {
        const withoutQuery = url.split(/[?#]/)[0] || "Unknown target";
        target = withoutQuery.startsWith("/") ? withoutQuery : "/redacted-target";
      }
      requests.push({
        method: typeof request?.method === "string" ? request.method : "GET",
        target,
        status: typeof response?.status === "number" ? response.status : 0,
        duration: typeof entry.time === "number" ? entry.time : null,
      });

      const postData = request?.postData as Record<string, unknown> | undefined;
      if (typeof postData?.text === "string") {
        postData.text = OMITTED_REQUEST_BODY;
        omittedBodies += 1;
      }
      const content = response?.content as Record<string, unknown> | undefined;
      if (typeof content?.text === "string") {
        content.text = OMITTED_RESPONSE_BODY;
        omittedBodies += 1;
      }
    }

    const sanitized = sanitizeNode(cloned, registry, "har");
    sanitizedHar = JSON.stringify(sanitized, null, 2);
  }

  if (consoleText) {
    let sanitized: unknown;
    try {
      sanitized = sanitizeNode(JSON.parse(consoleText), registry, "console");
      sanitizedConsole = JSON.stringify(sanitized, null, 2);
    } catch (error) {
      if (error instanceof SyntaxError) {
        sanitizedConsole = sanitizeString(consoleText, registry, "console.text");
      } else {
        throw error;
      }
    }
  }

  for (const term of customTerms.map((item) => item.trim()).filter(Boolean)) {
    const alias = registry.alias("SECRET", term, "custom rule");
    if (sanitizedHar) sanitizedHar = sanitizedHar.split(term).join(alias);
    if (sanitizedConsole) sanitizedConsole = sanitizedConsole.split(term).join(alias);
  }

  const entries = registry.values();
  const checked = audit([sanitizedHar ?? "", sanitizedConsole ?? ""], entries);
  return {
    sanitizedHar,
    sanitizedConsole,
    findings: entries,
    omittedBodies,
    requests,
    auditPassed: checked.passed,
    auditMessage: checked.message,
  };
}

export function findingsByCategory(findings: Finding[]) {
  return findings.reduce<Record<string, { entities: number; occurrences: number }>>((totals, finding) => {
    const current = totals[finding.category] ?? { entities: 0, occurrences: 0 };
    current.entities += 1;
    current.occurrences += finding.occurrences;
    totals[finding.category] = current;
    return totals;
  }, {});
}
