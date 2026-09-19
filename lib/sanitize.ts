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
  "userid",
  "accountid",
  "customerid",
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
    [
      "token",
      "secret",
      "password",
      "passwd",
      "apikey",
      "accesskey",
      "secretkey",
      "cookie",
      "credential",
      "userid",
      "accountid",
      "customerid",
      "sessionid",
    ].some(
      (suffix) => key.endsWith(suffix),
    )
  );
}

function categoryForSensitiveKey(value: string): FindingCategory {
  const key = normalizeKey(value);
  if (["userid", "accountid", "customerid"].some((suffix) => key.endsWith(suffix))) return "USER_ID";
  if (key.includes("session")) return "SESSION";
  if (key.includes("cookie")) return "COOKIE";
  if (key.includes("authorization") || key.startsWith("auth")) return "AUTH";
  if (["apikey", "accesskey", "secretkey"].some((suffix) => key.endsWith(suffix))) return "API_KEY";
  return "SECRET";
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
  private generatedAliases = new Set<string>();
  private reservedAliases: Set<string>;

  constructor(reservedAliases = new Set<string>()) {
    this.reservedAliases = reservedAliases;
  }

  isAlias(value: string) {
    return this.generatedAliases.has(value);
  }

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

    let count = (this.counters.get(category) ?? 0) + 1;
    let alias = `[${category}_${count}]`;
    while (alias === raw || this.reservedAliases.has(alias) || this.generatedAliases.has(alias)) {
      count += 1;
      alias = `[${category}_${count}]`;
    }
    this.counters.set(category, count);
    this.generatedAliases.add(alias);
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
      if (equals < 0) {
        if (!trimmed) return trimmed;
        if (
          setCookie &&
          index > 0 &&
          ["secure", "httponly", "partitioned"].includes(trimmed.toLowerCase())
        ) {
          return trimmed;
        }
        return registry.alias("COOKIE", trimmed, location);
      }
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
  if (registry.isAlias(match[2])) return `${match[1]} ${match[2]}`;
  return `${match[1]} ${registry.alias("AUTH", match[2], location)}`;
}

function sanitizeString(input: string, registry: Registry, location: string) {
  if (
    input === OMITTED_REQUEST_BODY ||
    input === OMITTED_RESPONSE_BODY ||
    registry.isAlias(input)
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
    /\b(https?:\/\/)([^/@\s]+)@/gi,
    (_, scheme: string, userInfo: string) => {
      const separator = userInfo.indexOf(":");
      if (separator < 0) {
        return `${scheme}${registry.alias("AUTH", userInfo, location)}@`;
      }
      const username = userInfo.slice(0, separator);
      const password = userInfo.slice(separator + 1);
      return `${scheme}${registry.alias("AUTH", username, location)}:${registry.alias("AUTH", password, location)}@`;
    },
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
    /(^|[\r\n])(\s*)(Cookie|Set-Cookie|Authorization|Proxy-Authorization)\s*:\s*([^\r\n]*)/gim,
    (
      _whole,
      lineStart: string,
      indentation: string,
      headerName: string,
      value: string,
    ) => {
      const normalizedName = headerName.toLowerCase();
      let sanitizedValue: string;
      if (normalizedName === "cookie") {
        sanitizedValue = sanitizeCookieHeader(value, registry, location);
      } else if (normalizedName === "set-cookie") {
        sanitizedValue = sanitizeCookieHeader(value, registry, location, true);
      } else {
        sanitizedValue = sanitizeAuthHeader(value, registry, location);
      }
      return `${lineStart}${indentation}${headerName}: ${sanitizedValue}`;
    },
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
    /\b(api[_-]?key|(?:aws[_-]?)?secret[_-]?access[_-]?key|access[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|(?:auth|authorization)(?:[_-]?token)?|token|client[_-]?secret|secret|password|passwd|pwd|session(?:[_-]?id)?|cookie)\b(\s*[:=]\s*)(["'])([^\r\n]{1,4096}?)\3/gi,
    (whole, key: string, separator: string, quote: string, value: string) =>
      (separator.includes(":") && ["cookie", "authorization"].includes(normalizeKey(key))) ||
      registry.isAlias(value)
        ? whole
        : `${key}${separator}${quote}${registry.alias(categoryForSensitiveKey(key), value, location)}${quote}`,
  );
  output = output.replace(
    /\b(api[_-]?key|(?:aws[_-]?)?secret[_-]?access[_-]?key|access[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|(?:auth|authorization)(?:[_-]?token)?|token|client[_-]?secret|secret|password|passwd|pwd|session(?:[_-]?id)?|cookie)\b(\s*[:=]\s*)(\[[A-Z_]+_\d+\]|[^\s,;&\]}"']+)/gi,
    (whole, key: string, separator: string, value: string) =>
      (separator.includes(":") && ["cookie", "authorization"].includes(normalizeKey(key))) ||
      registry.isAlias(value)
        ? whole
        : `${key}${separator}${registry.alias(categoryForSensitiveKey(key), value, location)}`,
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
    /\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+(?:\\[A-Za-z0-9._ -]+)*/g,
    "PATH",
    registry,
    location,
  );
  output = replaceWith(
    output,
    /\b[A-Za-z]:\\(?:Users|Documents and Settings)\\[A-Za-z0-9._-]+(?:\\[A-Za-z0-9._ -]+){1,}/g,
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
      if (registry.isAlias(decoded)) return whole;
      const category: FindingCategory = isSensitiveKey(key) ? "SECRET" : "QUERY";
      return `${prefix}${key}=${encodeURIComponent(registry.alias(category, decoded, location))}`;
    },
  );

  return output;
}

function nextUniqueKey(output: Record<string, unknown>, preferred: string) {
  if (!Object.prototype.hasOwnProperty.call(output, preferred)) return preferred;
  let suffix = 2;
  while (Object.prototype.hasOwnProperty.call(output, `${preferred}__${suffix}`)) suffix += 1;
  return `${preferred}__${suffix}`;
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
  const output = Object.create(null) as Record<string, unknown>;
  const headerName = typeof source.name === "string" ? source.name.toLowerCase() : "";
  const isHeaderPair = /\.headers\[\d+\]$/.test(path);
  for (const [key, child] of Object.entries(source)) {
    const sanitizedKey = sanitizeString(key, registry, path ? `${path}.[key]` : "[key]");
    const outputKey = nextUniqueKey(output, sanitizedKey);
    const childPath = path ? `${path}.${outputKey}` : outputKey;
    if (
      key === "value" &&
      isHeaderPair &&
      (SENSITIVE_HEADERS.has(headerName) || isSensitiveKey(headerName))
    ) {
      const rawValue = typeof child === "string" ? child : (JSON.stringify(child) ?? String(child));
      if (
        typeof child === "string" &&
        (headerName === "authorization" || headerName === "proxy-authorization")
      ) {
        output[outputKey] = sanitizeAuthHeader(child, registry, childPath);
      } else if (typeof child === "string" && headerName === "cookie") {
        output[outputKey] = sanitizeCookieHeader(child, registry, childPath);
      } else if (typeof child === "string" && headerName === "set-cookie") {
        output[outputKey] = sanitizeCookieHeader(child, registry, childPath, true);
      } else {
        output[outputKey] = registry.alias(categoryForSensitiveKey(headerName), rawValue, childPath);
      }
    } else if (isSensitiveKey(key) && (typeof child !== "object" || child === null)) {
      output[outputKey] =
        typeof child === "string"
          ? registry.alias(categoryForSensitiveKey(key), child, childPath)
          : registry.alias(categoryForSensitiveKey(key), JSON.stringify(child), childPath);
    } else if (isSensitiveKey(key) && child && typeof child === "object") {
      output[outputKey] = registry.alias(categoryForSensitiveKey(key), JSON.stringify(child), childPath);
    } else {
      output[outputKey] = sanitizeNode(child, registry, childPath, depth + 1);
    }
  }
  return output;
}

function escapedJsonString(value: string) {
  const serialized = JSON.stringify(value);
  return serialized.slice(1, -1);
}

function collectJsonAuditStrings(
  value: unknown,
  values: string[],
  keys: string[],
  depth = 0,
) {
  if (depth > 64) return;
  if (typeof value === "string") {
    values.push(value);
    return;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    values.push(String(value));
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => collectJsonAuditStrings(item, values, keys, depth + 1));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    keys.push(key);
    collectJsonAuditStrings(child, values, keys, depth + 1);
  }
}

type MatcherNode<T> = {
  next: Map<string, number>;
  fail: number;
  value?: T;
};

/** Find any known literal in one pass over the inputs. */
function firstMultiLiteralMatch<T>(inputs: string[], values: Map<string, T>) {
  if (!values.size) return undefined;

  const nodes: Array<MatcherNode<T>> = [{ next: new Map(), fail: 0 }];
  for (const [literal, value] of values) {
    if (!literal) continue;
    let state = 0;
    for (const character of literal) {
      const existing = nodes[state].next.get(character);
      if (existing !== undefined) {
        state = existing;
        continue;
      }
      const nextState = nodes.length;
      nodes[state].next.set(character, nextState);
      nodes.push({ next: new Map(), fail: 0 });
      state = nextState;
    }
    nodes[state].value ??= value;
  }

  const queue: number[] = [];
  for (const child of nodes[0].next.values()) queue.push(child);
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const state = queue[cursor];
    for (const [character, child] of nodes[state].next) {
      queue.push(child);
      let fallback = nodes[state].fail;
      while (fallback !== 0 && !nodes[fallback].next.has(character)) {
        fallback = nodes[fallback].fail;
      }
      const target = nodes[fallback].next.get(character);
      nodes[child].fail = target !== undefined && target !== child ? target : 0;
      nodes[child].value ??= nodes[nodes[child].fail].value;
    }
  }

  for (const input of inputs) {
    let state = 0;
    for (const character of input) {
      while (state !== 0 && !nodes[state].next.has(character)) {
        state = nodes[state].fail;
      }
      state = nodes[state].next.get(character) ?? 0;
      if (nodes[state].value !== undefined) return nodes[state].value;
    }
  }
  return undefined;
}

const aliasTokenPattern = /\[(?:AUTH|API_KEY|COOKIE|EMAIL|HOST|IP|PATH|PRIVATE_KEY|QUERY|SECRET|SESSION|USER_ID)_\d+\]|%5B(?:AUTH|API_KEY|COOKIE|EMAIL|HOST|IP|PATH|PRIVATE_KEY|QUERY|SECRET|SESSION|USER_ID)_\d+%5D/gi;
const percentEncoder = new TextEncoder();

function percentBytePattern(byte: number) {
  return byte
    .toString(16)
    .padStart(2, "0")
    .split("")
    .map((digit) => /[a-f]/.test(digit) ? `[${digit}${digit.toUpperCase()}]` : digit)
    .join("");
}

function percentAwareLiteralPattern(value: string) {
  return [...value].map((character) => {
    const encodedAtDepth = (depth: number, source = character) =>
      [...percentEncoder.encode(source)]
        .map((byte) => `%${"25".repeat(depth - 1)}${percentBytePattern(byte)}`)
        .join("");
    const alternatives = [escapeRegExp(character)];
    for (let depth = 1; depth <= 3; depth += 1) {
      alternatives.push(encodedAtDepth(depth));
    }
    if (character === " ") {
      alternatives.push("\\+");
      for (let depth = 1; depth <= 3; depth += 1) {
        alternatives.push(encodedAtDepth(depth, "+"));
      }
    }
    return `(?:${alternatives.join("|")})`;
  }).join("");
}

function normalizedAlias(token: string) {
  if (!token.startsWith("%")) return token;
  try {
    return decodeURIComponent(token);
  } catch {
    return token;
  }
}

function replaceOutsideGeneratedAliases(
  input: string,
  isGeneratedAlias: (value: string) => boolean,
  replaceSegment: (value: string) => string,
) {
  const parts: string[] = [];
  let cursor = 0;
  for (const match of input.matchAll(aliasTokenPattern)) {
    if (!isGeneratedAlias(normalizedAlias(match[0]))) continue;
    const index = match.index ?? 0;
    parts.push(replaceSegment(input.slice(cursor, index)), match[0]);
    cursor = index + match[0].length;
  }
  parts.push(replaceSegment(input.slice(cursor)));
  return parts.join("");
}

function decodePercentRuns(value: string, formEncoded = false) {
  const source = formEncoded ? value.replaceAll("+", " ") : value;
  return source.replace(/(?:%[0-9a-f]{2})+/gi, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      return run;
    }
  });
}

function auditProjections(value: string) {
  const projections = [value];
  let frontier = [value];
  for (let pass = 0; pass < 4 && frontier.length; pass += 1) {
    const next: string[] = [];
    for (const candidate of frontier) {
      for (const decoded of [
        decodePercentRuns(candidate),
        decodePercentRuns(candidate, true),
      ]) {
        if (decoded === candidate || projections.includes(decoded)) continue;
        projections.push(decoded);
        next.push(decoded);
      }
    }
    frontier = next;
  }
  return projections;
}

export function auditSanitizedOutputs(
  outputs: string[],
  findings: Array<Pick<Finding, "alias" | "category" | "raw">>,
) {
  const aliasToken = /\[(?:AUTH|API_KEY|COOKIE|EMAIL|HOST|IP|PATH|PRIVATE_KEY|QUERY|SECRET|SESSION|USER_ID)_\d+\]/g;
  const encodedAliasToken = /%5B(?:AUTH|API_KEY|COOKIE|EMAIL|HOST|IP|PATH|PRIVATE_KEY|QUERY|SECRET|SESSION|USER_ID)_\d+%5D/gi;
  const generatedAliases = new Set(
    findings.flatMap((finding) => [finding.alias, encodeURIComponent(finding.alias)]),
  );
  const conflictingAliases = new Set<string>();
  for (const finding of findings) {
    const canonical = canonicalize(finding.category, finding.raw);
    for (const rawVariant of new Set([finding.raw, canonical])) {
      const sourceVariants = [rawVariant, escapedJsonString(rawVariant)];
      try {
        sourceVariants.push(encodeURIComponent(rawVariant));
      } catch {
        // Ignore values that cannot be URI encoded.
      }
      for (const sourceVariant of sourceVariants) {
        for (const match of sourceVariant.matchAll(aliasToken)) {
          if (generatedAliases.has(match[0])) conflictingAliases.add(match[0]);
        }
        for (const match of sourceVariant.matchAll(encodedAliasToken)) {
          const normalized = match[0].toUpperCase();
          if (generatedAliases.has(normalized)) conflictingAliases.add(normalized);
        }
      }
    }
  }
  const aliases = new Set(
    [...generatedAliases].filter((alias) => !conflictingAliases.has(alias)),
  );
  const stripAliases = (value: string) => value
      .replace(aliasToken, (token) => aliases.has(token) ? "" : token)
      .replace(encodedAliasToken, (token) => aliases.has(token.toUpperCase()) ? "" : token);

  const structuredValues: string[] = [];
  const structuredKeys: string[] = [];
  const plainOutputs: string[] = [];
  for (const output of outputs) {
    try {
      const values: string[] = [];
      const keys: string[] = [];
      collectJsonAuditStrings(JSON.parse(output) as unknown, values, keys);
      structuredValues.push(...values.flatMap((value) => auditProjections(stripAliases(value))));
      structuredKeys.push(...keys.flatMap((value) => auditProjections(stripAliases(value))));
    } catch {
      plainOutputs.push(...auditProjections(stripAliases(output)));
    }
  }

  const exactValueCandidates = new Map<string, Pick<Finding, "alias" | "category" | "raw">>();
  const exactKeyCandidates = new Map<string, Pick<Finding, "alias" | "category" | "raw">>();
  const substringCandidates = new Map<string, Pick<Finding, "alias" | "category" | "raw">>();
  for (const finding of findings) {
    // Ordinary query values are redacted at their URL/queryString source only.
    // Treating generic values such as GET, OK, gzip, or application as global
    // secrets corrupts valid HAR metadata and creates false audit failures.
    if (finding.category === "QUERY") continue;
    if (/^\d+$/.test(finding.raw) && finding.raw.length < 8) continue;
    const canonical = canonicalize(finding.category, finding.raw);
    const rawVariants = new Set([finding.raw, canonical]);
    const patternCategory = ["EMAIL", "IP", "HOST", "PATH", "PRIVATE_KEY", "API_KEY"].includes(
      finding.category,
    );
    for (const rawVariant of rawVariants) {
      const variants = new Set([rawVariant, escapedJsonString(rawVariant)]);
      try {
        variants.add(encodeURIComponent(rawVariant));
      } catch {
        // Ignore values that cannot be URI encoded.
      }
      const substringIsReliable = patternCategory || rawVariant.length >= 8;
      const exactKeyMatchIsReliable = patternCategory || rawVariant.length >= 8;
      for (const candidate of variants) {
        if (!candidate) continue;
        if (!exactValueCandidates.has(candidate)) exactValueCandidates.set(candidate, finding);
        if (exactKeyMatchIsReliable && !exactKeyCandidates.has(candidate)) {
          exactKeyCandidates.set(candidate, finding);
        }
        if (substringIsReliable && !substringCandidates.has(candidate)) {
          substringCandidates.set(candidate, finding);
        }
      }
    }
  }
  let exactFinding: Pick<Finding, "alias" | "category" | "raw"> | undefined;
  for (const value of structuredValues) {
    exactFinding = exactValueCandidates.get(value);
    if (exactFinding) break;
  }
  if (!exactFinding) {
    for (const key of structuredKeys) {
      exactFinding = exactKeyCandidates.get(key);
      if (exactFinding) break;
    }
  }
  const substringFinding = firstMultiLiteralMatch(
    [...structuredValues, ...structuredKeys, ...plainOutputs],
    substringCandidates,
  );
  const leakedFinding = exactFinding ?? substringFinding;
  if (leakedFinding) {
    return {
      passed: false,
      message: `A ${leakedFinding.category.toLowerCase()} value survived the privacy audit.`,
    };
  }
  const joined = [...structuredValues, ...structuredKeys, ...plainOutputs].join("\n");
  if (
    /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/.test(joined) ||
    /\bBearer[ \t]+[A-Za-z0-9._~+/=-]{8,}/i.test(joined)
  ) {
    return { passed: false, message: "A high-confidence credential survived the privacy audit." };
  }
  return { passed: true, message: "No known source value remains in the sanitized text files." };
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function aliasHarValues(
  value: unknown,
  registry: Registry,
  path: string,
  categoryForName: (name: string) => FindingCategory,
) {
  if (!Array.isArray(value)) return;
  value.forEach((item, index) => {
    const record = asRecord(item);
    if (!record || !Object.prototype.hasOwnProperty.call(record, "value")) return;
    const rawValue = record.value;
    if (rawValue === undefined) return;
    const raw = typeof rawValue === "string" ? rawValue : JSON.stringify(rawValue);
    if (raw === undefined) return;
    const name = typeof record.name === "string" ? record.name : "";
    record.value = registry.alias(categoryForName(name), raw, `${path}[${index}].value`);
  });
}

function prepareHar(value: unknown, registry: Registry) {
  let omittedBodies = 0;
  const root = asRecord(value);
  const log = asRecord(root?.log);
  const entries = Array.isArray(log?.entries) ? log.entries : [];

  entries.forEach((item, index) => {
    const entry = asRecord(item);
    if (!entry) return;
    const request = asRecord(entry.request);
    const response = asRecord(entry.response);

    aliasHarValues(
      request?.queryString,
      registry,
      `har.log.entries[${index}].request.queryString`,
      (name) => isSensitiveKey(name) ? "SECRET" : "QUERY",
    );
    aliasHarValues(
      request?.cookies,
      registry,
      `har.log.entries[${index}].request.cookies`,
      (name) => normalizeKey(name).includes("session") ? "SESSION" : "COOKIE",
    );
    aliasHarValues(
      response?.cookies,
      registry,
      `har.log.entries[${index}].response.cookies`,
      (name) => normalizeKey(name).includes("session") ? "SESSION" : "COOKIE",
    );

    const hasPostData = Boolean(request && Object.prototype.hasOwnProperty.call(request, "postData"));
    const postData = asRecord(request?.postData);
    if (hasPostData && !postData && request) {
      request.postData = OMITTED_REQUEST_BODY;
      omittedBodies += 1;
    } else {
      if (postData && Object.prototype.hasOwnProperty.call(postData, "text")) {
        postData.text = OMITTED_REQUEST_BODY;
        omittedBodies += 1;
      }
      if (postData && Object.prototype.hasOwnProperty.call(postData, "params")) {
        postData.params = OMITTED_REQUEST_BODY;
        omittedBodies += 1;
      }
    }

    const hasContent = Boolean(response && Object.prototype.hasOwnProperty.call(response, "content"));
    const content = asRecord(response?.content);
    if (hasContent && !content && response) {
      response.content = OMITTED_RESPONSE_BODY;
      omittedBodies += 1;
    } else if (content && Object.prototype.hasOwnProperty.call(content, "text")) {
      content.text = OMITTED_RESPONSE_BODY;
      delete content.encoding;
      omittedBodies += 1;
    }
  });

  return omittedBodies;
}

type PropagationChunk = {
  pattern: RegExp;
  findingsByRaw: Map<string, RegistryEntry>;
};

type PropagationPlan = {
  chunks: PropagationChunk[];
  findingsByRaw: Map<string, RegistryEntry>;
  aliases: Set<string>;
};

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function createPropagationPlan(findings: RegistryEntry[]): PropagationPlan {
  const findingsByRaw = new Map<string, RegistryEntry>();
  for (const finding of findings) {
    for (const literal of new Set([finding.raw, finding.canonical])) {
      if (
        literal &&
        (literal.length >= 8 || ["EMAIL", "IP", "HOST", "PATH", "PRIVATE_KEY", "API_KEY"].includes(finding.category)) &&
        !findingsByRaw.has(literal)
      ) {
        findingsByRaw.set(literal, finding);
      }
    }
  }
  const sorted = [...findingsByRaw.entries()]
    .map(([literal, finding]) => ({ literal, finding }))
    .sort((left, right) => right.literal.length - left.literal.length);
  const chunks: PropagationChunk[] = [];
  let chunkEntries: Array<{ literal: string; finding: RegistryEntry }> = [];
  let chunkPatternLength = 0;

  const flush = () => {
    if (!chunkEntries.length) return;
    const byRaw = new Map(chunkEntries.map(({ literal, finding }) => [literal, finding]));
    chunks.push({
      pattern: new RegExp(chunkEntries.map(({ literal }) => escapeRegExp(literal)).join("|"), "g"),
      findingsByRaw: byRaw,
    });
    chunkEntries = [];
    chunkPatternLength = 0;
  };

  for (const entry of sorted) {
    const escapedLength = escapeRegExp(entry.literal).length + 1;
    if (chunkEntries.length >= 50_000 || chunkPatternLength + escapedLength > 2_000_000) flush();
    chunkEntries.push(entry);
    chunkPatternLength += escapedLength;
  }
  flush();
  const generatedAliases = new Set(findings.map((finding) => finding.alias));
  const conflictingAliases = new Set<string>();
  const aliasPattern = /\[(?:AUTH|API_KEY|COOKIE|EMAIL|HOST|IP|PATH|PRIVATE_KEY|QUERY|SECRET|SESSION|USER_ID)_\d+\]/g;
  for (const finding of findings) {
    for (const rawVariant of new Set([finding.raw, finding.canonical])) {
      for (const match of rawVariant.matchAll(aliasPattern)) {
        if (generatedAliases.has(match[0])) conflictingAliases.add(match[0]);
      }
    }
  }
  return {
    chunks,
    findingsByRaw,
    aliases: new Set([...generatedAliases].filter((alias) => !conflictingAliases.has(alias))),
  };
}

function replaceKnownValuesInString(
  input: string,
  plan: PropagationPlan,
  registry: Registry,
  path: string,
) {
  let output = input;
  const replaceOutsideAliases = (replaceSegment: (segment: string) => string) => {
    const aliasPattern = /\[(?:AUTH|API_KEY|COOKIE|EMAIL|HOST|IP|PATH|PRIVATE_KEY|QUERY|SECRET|SESSION|USER_ID)_\d+\]/g;
    const parts: string[] = [];
    let cursor = 0;
    for (const match of output.matchAll(aliasPattern)) {
      if (!plan.aliases.has(match[0])) continue;
      const index = match.index ?? 0;
      parts.push(replaceSegment(output.slice(cursor, index)), match[0]);
      cursor = index + match[0].length;
    }
    parts.push(replaceSegment(output.slice(cursor)));
    output = parts.join("");
  };
  for (const chunk of plan.chunks) {
    replaceOutsideAliases((segment) => segment.replace(chunk.pattern, (raw) => {
      const finding = chunk.findingsByRaw.get(raw);
      return finding ? registry.alias(finding.category, raw, path) : raw;
    }));
  }
  return output;
}

function propagateKnownValues(
  value: unknown,
  plan: PropagationPlan,
  registry: Registry,
  path: string,
  keyPlan: PropagationPlan | null,
  depth = 0,
): unknown {
  if (depth > 64) throw new Error("Input nesting is too deep to process safely.");
  if (typeof value === "string") {
    return replaceKnownValuesInString(value, plan, registry, path);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    const raw = String(value);
    const finding = plan.findingsByRaw.get(raw);
    return finding ? registry.alias(finding.category, raw, path) : value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) =>
      propagateKnownValues(item, plan, registry, `${path}[${index}]`, keyPlan, depth + 1),
    );
  }
  if (!value || typeof value !== "object") return value;

  const output = Object.create(null) as Record<string, unknown>;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const propagatedKey = keyPlan
      ? replaceKnownValuesInString(key, keyPlan, registry, `${path}.[key]`)
      : key;
    const outputKey = nextUniqueKey(output, propagatedKey);
    output[outputKey] = propagateKnownValues(
      child,
      plan,
      registry,
      `${path}.${outputKey}`,
      keyPlan,
      depth + 1,
    );
  }
  return output;
}

function replaceCustomTerm(
  value: unknown,
  term: string,
  registry: Registry,
  path: string,
  depth = 0,
): unknown {
  if (depth > 64) throw new Error("Input nesting is too deep to process safely.");
  if (typeof value === "string") {
    const pattern = new RegExp(percentAwareLiteralPattern(term), "g");
    return replaceOutsideGeneratedAliases(
      value,
      (candidate) => registry.isAlias(candidate),
      (segment) => segment.replace(pattern, () => registry.alias("SECRET", term, path)),
    );
  }
  if (typeof value === "number" && Number.isFinite(value) && String(value) === term) {
    return registry.alias("SECRET", term, path);
  }
  if (Array.isArray(value)) {
    return value.map((item, index) =>
      replaceCustomTerm(item, term, registry, `${path}[${index}]`, depth + 1),
    );
  }
  if (!value || typeof value !== "object") return value;

  const output = Object.create(null) as Record<string, unknown>;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const keyPath = `${path}.[key]`;
    const pattern = new RegExp(percentAwareLiteralPattern(term), "g");
    const replacedKey = replaceOutsideGeneratedAliases(
      key,
      (candidate) => registry.isAlias(candidate),
      (segment) => segment.replace(pattern, () => registry.alias("SECRET", term, keyPath)),
    );
    const outputKey = nextUniqueKey(output, replacedKey);
    output[outputKey] = replaceCustomTerm(child, term, registry, `${path}.${outputKey}`, depth + 1);
  }
  return output;
}

function looksLikeHar(value: unknown) {
  const root = asRecord(value);
  const log = asRecord(root?.log);
  return Boolean(log && Object.prototype.hasOwnProperty.call(log, "entries"));
}

function harEnvelope(value: unknown) {
  const root = asRecord(value);
  const log = asRecord(root?.log);
  if (!log || typeof log.version !== "string" || !Array.isArray(log.entries)) return null;
  return { entries: log.entries };
}

function assertValidHar(value: unknown) {
  const envelope = harEnvelope(value);
  if (!envelope) throw new Error("The network archive is not a valid HAR document.");
  for (const entry of envelope.entries) {
    const record = asRecord(entry);
    if (!record || !asRecord(record.request) || !asRecord(record.response)) {
      throw new Error("The network archive contains an invalid HAR entry.");
    }
  }
}

function requestTarget(url: string) {
  let target: string;
  try {
    target = new URL(url).pathname || "/";
  } catch {
    const schemeIndex = url.indexOf("://");
    const pathStart = schemeIndex >= 0 ? url.indexOf("/", schemeIndex + 3) : -1;
    const candidate = pathStart >= 0 ? url.slice(pathStart) : url;
    const withoutQuery = candidate.split(/[?#]/)[0] || "Unknown target";
    target = withoutQuery.startsWith("/") ? withoutQuery : "/redacted-target";
  }
  return target.replaceAll("`", "%60").replace(/[\r\n]/g, "");
}

function extractRequestSummaries(sanitizedHar: string): RequestSummary[] {
  const parsed = JSON.parse(sanitizedHar) as unknown;
  const root = asRecord(parsed);
  const log = asRecord(root?.log);
  const entries = Array.isArray(log?.entries) ? log.entries : [];
  const requests: RequestSummary[] = [];

  for (const item of entries) {
    const entry = asRecord(item);
    if (!entry) continue;
    const request = asRecord(entry.request);
    const response = asRecord(entry.response);
    const rawMethod = typeof request?.method === "string" ? request.method : "";
    const method = /^[A-Z]{1,12}$/.test(rawMethod) ? rawMethod : "HTTP";
    const url = typeof request?.url === "string" ? request.url : "";
    requests.push({
      method,
      target: requestTarget(url),
      status: typeof response?.status === "number" ? response.status : 0,
      duration: typeof entry.time === "number" ? entry.time : null,
    });
  }
  return requests;
}

function collectReservedAliases(inputs: string[]) {
  const reserved = new Set<string>();
  const aliasPattern = /\[(?:AUTH|API_KEY|COOKIE|EMAIL|HOST|IP|PATH|PRIVATE_KEY|QUERY|SECRET|SESSION|USER_ID)_\d+\]/g;
  const encodedAliasPattern = /%5B(?:AUTH|API_KEY|COOKIE|EMAIL|HOST|IP|PATH|PRIVATE_KEY|QUERY|SECRET|SESSION|USER_ID)_\d+%5D/gi;
  for (const input of inputs) {
    const normalized = input
      .replace(/\\u005b/gi, "[")
      .replace(/\\u005d/gi, "]");
    for (const match of normalized.matchAll(aliasPattern)) reserved.add(match[0]);
    for (const match of normalized.matchAll(encodedAliasPattern)) {
      try {
        reserved.add(decodeURIComponent(match[0]));
      } catch {
        // The fixed alias pattern should always decode, but fail closed if it does not.
        reserved.add(match[0]);
      }
    }
  }
  return reserved;
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
  const registry = new Registry(collectReservedAliases([
    harText ?? "",
    consoleText ?? "",
    ...customTerms,
  ]));
  let sanitizedHar: string | undefined;
  let sanitizedConsole: string | undefined;
  let omittedBodies = 0;
  let consoleIsJson = false;

  if (harText) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(harText) as unknown;
    } catch {
      throw new Error("The HAR file is not valid JSON.");
    }
    assertValidHar(parsed);
    omittedBodies += prepareHar(parsed, registry);
    const sanitized = sanitizeNode(parsed, registry, "har");
    sanitizedHar = JSON.stringify(sanitized, null, 2);
  }

  if (consoleText) {
    let sanitized: unknown;
    try {
      const parsed = JSON.parse(consoleText) as unknown;
      if (looksLikeHar(parsed)) {
        throw new Error("This JSON looks like a HAR archive. Import it as a .har file so request and response bodies are safely omitted.");
      }
      sanitized = sanitizeNode(parsed, registry, "console");
      sanitizedConsole = JSON.stringify(sanitized, null, 2);
      consoleIsJson = true;
    } catch (error) {
      if (error instanceof SyntaxError) {
        sanitizedConsole = sanitizeString(consoleText, registry, "console.text");
      } else {
        throw error;
      }
    }
  }

  const initiallyDiscovered = registry.values();
  const propagationPlan = createPropagationPlan(
    initiallyDiscovered.filter((finding) => finding.category !== "QUERY"),
  );
  const harKeyPlan = createPropagationPlan(
    initiallyDiscovered.filter((finding) => finding.category !== "QUERY"),
  );
  if (initiallyDiscovered.length && sanitizedHar) {
    const parsed = JSON.parse(sanitizedHar) as unknown;
    sanitizedHar = JSON.stringify(
      propagateKnownValues(parsed, propagationPlan, registry, "har.propagated", harKeyPlan),
      null,
      2,
    );
  }
  if (initiallyDiscovered.length && sanitizedConsole) {
    if (consoleIsJson) {
      const parsed = JSON.parse(sanitizedConsole) as unknown;
      sanitizedConsole = JSON.stringify(
        propagateKnownValues(parsed, propagationPlan, registry, "console.propagated", propagationPlan),
        null,
        2,
      );
    } else {
      sanitizedConsole = replaceKnownValuesInString(
        sanitizedConsole,
        propagationPlan,
        registry,
        "console.propagated",
      );
    }
  }

  for (const term of customTerms.map((item) => item.trim()).filter(Boolean)) {
    if (sanitizedHar) {
      const parsed = JSON.parse(sanitizedHar) as unknown;
      sanitizedHar = JSON.stringify(replaceCustomTerm(parsed, term, registry, "har.custom"), null, 2);
    }
    if (sanitizedConsole) {
      if (consoleIsJson) {
        const parsed = JSON.parse(sanitizedConsole) as unknown;
        sanitizedConsole = JSON.stringify(
          replaceCustomTerm(parsed, term, registry, "console.custom"),
          null,
          2,
        );
      } else {
        sanitizedConsole = replaceCustomTerm(
          sanitizedConsole,
          term,
          registry,
          "console.custom",
        ) as string;
      }
    }
  }

  const entries = registry.values();
  const requests = sanitizedHar ? extractRequestSummaries(sanitizedHar) : [];
  const checked = auditSanitizedOutputs([sanitizedHar ?? "", sanitizedConsole ?? ""], entries);
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
