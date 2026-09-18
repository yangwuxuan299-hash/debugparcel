import assert from "node:assert/strict";
import test from "node:test";

const sanitizeModuleUrl = new URL("../lib/sanitize.ts", import.meta.url).href;
const { auditSanitizedOutputs, scanDiagnostics } = await import(sanitizeModuleUrl) as typeof import("../lib/sanitize");

function harWithEntry(entry: Record<string, unknown>) {
  return JSON.stringify({
    log: {
      version: "1.2",
      creator: { name: "test", version: "1" },
      entries: [entry],
    },
  });
}

test("request summaries are derived from the final sanitized HAR", () => {
  const email = "alice@example.com";
  const customTerm = "tenant-secret";
  const result = scanDiagnostics({
    harText: harWithEntry({
      time: 12,
      request: {
        method: "GET\n`injected`",
        url: `https://api.example.com/users/${email}/${customTerm}`,
      },
      response: { status: 500, content: {} },
    }),
    customTerms: [customTerm],
  });

  assert.equal(result.auditPassed, true);
  assert.equal(result.requests.length, 1);
  assert.equal(result.requests[0].method, "HTTP");
  assert.doesNotMatch(result.requests[0].target, /alice@example\.com|tenant-secret/);
  assert.match(result.requests[0].target, /\[EMAIL_\d+\]/);
  assert.match(result.requests[0].target, /\[SECRET_\d+\]/);
});

test("HAR query values, cookies, and every body representation are sanitized", () => {
  const result = scanDiagnostics({
    harText: harWithEntry({
      time: 27,
      request: {
        method: "POST",
        url: "https://api.example.com/submit?trace=opaque-query-value",
        queryString: [{ name: "trace", value: "opaque-query-value" }],
        cookies: [{ name: "session_id", value: "opaque-request-cookie" }],
        postData: {
          mimeType: "multipart/form-data",
          text: "raw-request-body",
          params: [{ name: "note", value: "raw-multipart-value" }],
        },
      },
      response: {
        status: 400,
        cookies: [{ name: "preference", value: "opaque-response-cookie" }],
        content: {
          mimeType: "application/json",
          text: "cmF3LXJlc3BvbnNlLWJvZHk=",
          encoding: "base64",
        },
      },
    }),
  });

  assert.equal(result.auditPassed, true);
  assert.equal(result.omittedBodies, 3);
  const sanitized = JSON.parse(result.sanitizedHar ?? "null") as {
    log: { entries: Array<Record<string, unknown>> };
  };
  const entry = sanitized.log.entries[0] as {
    request: {
      queryString: Array<{ value: string }>;
      cookies: Array<{ value: string }>;
      postData: { text: string; params: string };
    };
    response: {
      cookies: Array<{ value: string }>;
      content: { text: string; encoding?: string };
    };
  };

  assert.match(entry.request.queryString[0].value, /^\[QUERY_\d+\]$/);
  assert.match(entry.request.cookies[0].value, /^\[SESSION_\d+\]$/);
  assert.match(entry.response.cookies[0].value, /^\[COOKIE_\d+\]$/);
  assert.equal(entry.request.postData.text, "[REQUEST_BODY_OMITTED]");
  assert.equal(entry.request.postData.params, "[REQUEST_BODY_OMITTED]");
  assert.equal(entry.response.content.text, "[RESPONSE_BODY_OMITTED]");
  assert.equal("encoding" in entry.response.content, false);

  for (const raw of [
    "opaque-query-value",
    "opaque-request-cookie",
    "opaque-response-cookie",
    "raw-request-body",
    "raw-multipart-value",
    "cmF3LXJlc3BvbnNlLWJvZHk=",
  ]) {
    assert.doesNotMatch(result.sanitizedHar ?? "", new RegExp(raw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("identity and session headers are classified from normalized header names", () => {
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "GET",
        url: "https://api.example.com/private",
        headers: [
          { name: "X-User-ID", value: "12345678" },
          { name: "X-Account-ID", value: "account-7788" },
          { name: "X-Session-ID", value: "session-value-42" },
        ],
      },
      response: { status: 200, content: {} },
    }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedHar ?? "", /12345678|account-7788|session-value-42/);
  assert.ok(result.findings.some((finding) => finding.category === "USER_ID"));
  assert.ok(result.findings.some((finding) => finding.category === "SESSION"));
});

test("malformed cookie and non-string credential headers fail closed", () => {
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "GET",
        url: "https://api.example.com/private",
        headers: [
          { name: "Cookie", value: "supersecret" },
          { name: "Authorization", value: { opaque: "topsecret" } },
          { name: "X-Api-Key", value: 123456789 },
        ],
      },
      response: { status: 200, content: {} },
    }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedHar ?? "", /supersecret|topsecret|123456789/);
  assert.ok(result.findings.some((finding) => finding.category === "COOKIE"));
  assert.ok(result.findings.some((finding) => finding.category === "AUTH"));
  assert.ok(result.findings.some((finding) => finding.category === "API_KEY"));
});

test("common query words do not collide with HAR schema keys or MIME values", () => {
  for (const queryValue of ["response", "application", "GET", "OK", "gzip"]) {
    const result = scanDiagnostics({
      harText: harWithEntry({
        request: {
          method: "GET",
          url: `https://api.example.com/search?q=${queryValue}`,
          queryString: [{ name: "q", value: queryValue }],
          headers: [{ name: "Accept", value: "application/json" }],
        },
        response: {
          status: 200,
          statusText: "OK",
          content: { mimeType: "application/json", encoding: "gzip" },
        },
      }),
    });

    assert.equal(result.auditPassed, true, queryValue);
    assert.doesNotMatch(result.requests[0].target, new RegExp(queryValue));
    const sanitized = JSON.parse(result.sanitizedHar ?? "null") as {
      log: { entries: Array<{
        request: { method: string; headers: Array<{ value: string }> };
        response: { statusText: string; content: { mimeType: string; encoding: string } };
      }> };
    };
    const entry = sanitized.log.entries[0];
    assert.equal(entry.request.method, "GET");
    assert.equal(entry.request.headers[0].value, "application/json");
    assert.equal(entry.response.statusText, "OK");
    assert.equal(entry.response.content.mimeType, "application/json");
    assert.equal(entry.response.content.encoding, "gzip");
  }
});

test("discovered cookie values are propagated across evidence files", () => {
  const raw = "supersecret";
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "GET",
        url: "https://api.example.com/private",
        cookies: [{ name: "auth_cookie", value: raw }],
      },
      response: { status: 200, content: {} },
    }),
    consoleText: JSON.stringify({ note: `cookie copied as copy=${raw}` }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /supersecret/);
  assert.match(result.sanitizedConsole ?? "", /\[COOKIE_\d+\]/);
});

test("alias-looking text cannot hide a copied secret", () => {
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "GET",
        url: "https://api.example.com/private",
        cookies: [{ name: "auth_cookie", value: "SUPERSECRET" }],
      },
      response: { status: 200, content: {} },
    }),
    consoleText: JSON.stringify({ message: "copied=[SUPERSECRET_1]" }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /SUPERSECRET/);
});

test("canonical whitespace and quote variants are propagated", () => {
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "GET",
        url: "https://api.example.com/private",
        cookies: [{ name: "auth_cookie", value: " supersecret " }],
      },
      response: { status: 200, content: {} },
    }),
    consoleText: JSON.stringify({ message: "copy=supersecret" }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /supersecret/);
});

test("short canonical variants do not collide with legitimate object keys", () => {
  const result = scanDiagnostics({
    consoleText: JSON.stringify({ secret: " secret " }),
  });

  assert.equal(result.auditPassed, true);
  assert.equal(JSON.parse(result.sanitizedConsole ?? "null").secret, "[SECRET_1]");
});

test("alias-shaped source values never collide with generated aliases", () => {
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "GET",
        url: "https://api.example.com/private",
        cookies: [{ name: "auth_cookie", value: "[COOKIE_1]" }],
      },
      response: { status: 200, content: {} },
    }),
    consoleText: JSON.stringify({ message: "copy=[COOKIE_1]" }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedHar ?? "", /\[COOKIE_1\]/);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /\[COOKIE_1\]/);
  assert.match(result.sanitizedConsole ?? "", /\[COOKIE_2\]/);
});

test("aliases that collide across categories cannot hide source values", () => {
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "GET",
        url: "https://api.example.com/private?token=actual-secret-value",
        queryString: [{ name: "token", value: "actual-secret-value" }],
        cookies: [{ name: "auth_cookie", value: "[SECRET_1]" }],
      },
      response: { status: 200, content: {} },
    }),
    consoleText: JSON.stringify({ message: "copy=[SECRET_1]" }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedHar ?? "", /\[SECRET_1\]/);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /\[SECRET_1\]/);
});

test("alias tokens embedded inside a source value are not treated as generated placeholders", () => {
  const raw = "prefix[SECRET_1]suffix";
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "GET",
        url: "https://api.example.com/private?token=actual-secret-value",
        queryString: [{ name: "token", value: "actual-secret-value" }],
        cookies: [{ name: "auth_cookie", value: raw }],
      },
      response: { status: 200, content: {} },
    }),
    consoleText: JSON.stringify({ message: `copy=${raw}` }),
  });

  assert.equal(result.auditPassed, true);
  assert.equal(result.sanitizedConsole?.includes(raw), false);
  assert.match(result.sanitizedConsole ?? "", /\[COOKIE_\d+\]/);
});

test("alias-shaped values in sensitive text contexts are treated as source data", () => {
  for (const consoleText of [
    "password=[SECRET_1]",
    "Authorization: Bearer [SECRET_1]",
    "GET /?q=[QUERY_1]",
    "GET /?q=%5BQUERY_1%5D",
  ]) {
    const result = scanDiagnostics({ consoleText });
    assert.equal(result.auditPassed, true, consoleText);
    assert.ok(result.findings.length > 0, consoleText);
    assert.notEqual(result.sanitizedConsole, consoleText);
  }
});

test("quoted assignments remain syntactically intact after redaction", () => {
  const result = scanDiagnostics({
    consoleText: 'password="foobar123"\nsecret=\'abcdefgh\'',
  });

  assert.equal(result.auditPassed, true);
  assert.equal(result.findings.length, 2);
  assert.match(result.sanitizedConsole ?? "", /^password="\[SECRET_\d+\]"$/m);
  assert.match(result.sanitizedConsole ?? "", /^secret='\[SECRET_\d+\]'$/m);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /\]\]"|\]\]'/);
});

test("AWS-style access and secret key fields are sanitized", () => {
  const result = scanDiagnostics({
    consoleText: JSON.stringify({
      aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      secretAccessKey: "another-long-secret-access-key",
      "x-secret-key": "custom-secret-key-value",
    }),
  });

  assert.equal(result.auditPassed, true);
  assert.equal(result.findings.length, 3);
  assert.ok(result.findings.every((finding) => finding.category === "API_KEY"));
  assert.doesNotMatch(result.sanitizedConsole ?? "", /wJalr|another-long|custom-secret/);
});

test("AWS-style keys in plain environment logs are sanitized", () => {
  const result = scanDiagnostics({
    consoleText: [
      "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "secret_access_key: another-long-secret-access-key",
    ].join("\n"),
  });

  assert.equal(result.auditPassed, true);
  assert.equal(result.findings.length, 2);
  assert.ok(result.findings.every((finding) => finding.category === "API_KEY"));
  assert.doesNotMatch(result.sanitizedConsole ?? "", /wJalr|another-long/);
});

test("non-string HAR bodies are omitted instead of recursively exported", () => {
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "POST",
        url: "https://api.example.com/private",
        postData: { text: { note: "opaque-request-value" } },
      },
      response: {
        status: 500,
        content: { text: { note: "opaque-response-value" }, encoding: "base64" },
      },
    }),
  });

  assert.equal(result.omittedBodies, 2);
  assert.doesNotMatch(result.sanitizedHar ?? "", /opaque-request-value|opaque-response-value|base64/);
  assert.match(result.sanitizedHar ?? "", /REQUEST_BODY_OMITTED/);
  assert.match(result.sanitizedHar ?? "", /RESPONSE_BODY_OMITTED/);
});

test("malformed HAR body containers are omitted wholesale", () => {
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "POST",
        url: "https://api.example.com/private",
        postData: "opaque-body-secret",
      },
      response: {
        status: 500,
        content: ["opaque-response-secret"],
      },
    }),
  });

  assert.equal(result.auditPassed, true);
  assert.equal(result.omittedBodies, 2);
  assert.doesNotMatch(result.sanitizedHar ?? "", /opaque-body-secret|opaque-response-secret/);
  assert.match(result.sanitizedHar ?? "", /REQUEST_BODY_OMITTED/);
  assert.match(result.sanitizedHar ?? "", /RESPONSE_BODY_OMITTED/);
});

test("numeric sensitive identifiers are propagated to matching scalar values", () => {
  const result = scanDiagnostics({
    consoleText: JSON.stringify({ userId: 12345678, messageId: 12345678 }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /12345678/);
  assert.match(result.sanitizedConsole ?? "", /\[USER_ID_\d+\]/);
});

test("known non-query values are propagated into extension object keys", () => {
  const raw = "abcdefgh";
  const result = scanDiagnostics({
    harText: harWithEntry({
      request: {
        method: "GET",
        url: "https://api.example.com/private",
        cookies: [{ name: "auth_cookie", value: raw }],
      },
      response: { status: 200, content: {} },
      extension: { [raw]: "copied into a custom key" },
    }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedHar ?? "", /abcdefgh/);
});

test("thousands of findings are propagated without quadratic slowdown", () => {
  const entries = Array.from({ length: 2_000 }, (_, index) => ({
    request: {
      method: "GET",
      url: `https://api.example.com/items/${index}?trace=opaque-query-${index}-value`,
      queryString: [{ name: "trace", value: `opaque-query-${index}-value` }],
    },
    response: { status: 200, content: { mimeType: "application/json" } },
  }));
  const startedAt = performance.now();
  const result = scanDiagnostics({
    harText: JSON.stringify({ log: { version: "1.2", entries } }),
  });
  const elapsed = performance.now() - startedAt;

  assert.equal(result.auditPassed, true);
  assert.equal(result.requests.length, entries.length);
  assert.ok(elapsed < 3_000, `2,000 findings took ${Math.round(elapsed)} ms`);
});

test("privacy audit detects JSON-escaped source values", () => {
  const raw = "line one\n\"quoted\"\\tail";
  const output = JSON.stringify({ value: raw });
  const audit = auditSanitizedOutputs([output], [
    { alias: "[SECRET_1]", category: "SECRET", raw },
  ]);

  assert.equal(audit.passed, false);
});

test("privacy audit does not mistake a short raw value inside its own alias for a leak", () => {
  const audit = auditSanitizedOutputs(['{"value":"[SECRET_1]","auditPassed":true,"count":1}'], [
    { alias: "[SECRET_1]", category: "SECRET", raw: "1" },
  ]);

  assert.equal(audit.passed, true);
});

test("privacy audit preserves every JSON field while ignoring generated aliases", () => {
  const audit = auditSanitizedOutputs(
    ['{"[EMAIL_1]":"supersecret","[EMAIL_2]":"safe"}'],
    [
      { alias: "[EMAIL_1]", category: "EMAIL", raw: "alice@example.com" },
      { alias: "[EMAIL_2]", category: "EMAIL", raw: "bob@example.com" },
      { alias: "[COOKIE_1]", category: "COOKIE", raw: "supersecret" },
    ],
  );

  assert.equal(audit.passed, false);
});

test("plain-text assignments, URL userinfo, and structured user IDs are sanitized", () => {
  const result = scanDiagnostics({
    consoleText: JSON.stringify({
      message: 'password="correct horse battery staple" url=https://alice:hunter2@example.com/private',
      userId: "123456",
    }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /correct horse|alice|hunter2|123456/);
  assert.ok(result.findings.some((finding) => finding.category === "AUTH"));
  assert.ok(result.findings.some((finding) => finding.category === "USER_ID"));
});

test("Windows user and UNC paths are sanitized", () => {
  const result = scanDiagnostics({
    consoleText: JSON.stringify({
      local: "C:\\Users\\alice\\project\\private.log",
      share: "\\\\fileserver\\support$\\alice\\trace.har",
    }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /alice|fileserver|private\.log|trace\.har/);
  assert.equal(result.findings.filter((finding) => finding.category === "PATH").length, 2);
});

test("plain-text cookie and authorization header lines are fully sanitized", () => {
  const result = scanDiagnostics({
    consoleText: [
      "Cookie: foo=alpha12345; bar=bravo67890",
      'Authorization: Digest username="alice", realm="private", response="digest-secret"',
    ].join("\n"),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /alpha12345|bravo67890|alice|private|digest-secret/);
  assert.match(result.sanitizedConsole ?? "", /Cookie: foo=\[COOKIE_\d+\]; bar=\[COOKIE_\d+\]/);
  assert.match(result.sanitizedConsole ?? "", /Authorization: \[AUTH_\d+\]/);
});

test("Bearer header lines reuse the first generated alias", () => {
  const result = scanDiagnostics({
    consoleText: "Authorization: Bearer abcdefghijklmnop",
  });

  assert.equal(result.auditPassed, true);
  assert.equal(result.findings.length, 1);
  assert.equal(result.sanitizedConsole, "Authorization: Bearer [AUTH_1]");
});

test("final credential audit never joins sanitized values across lines", () => {
  const result = scanDiagnostics({
    consoleText: 'Authorization: Bearer abcdefghijklmnop\npassword="foobar123"',
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /abcdefghijklmnop|foobar123/);
});

test("custom rule occurrence totals reflect every replacement", () => {
  const term = "AcmeTenant42";
  const result = scanDiagnostics({
    consoleText: JSON.stringify({ [term]: `${term} and ${term}` }),
    customTerms: [term],
  });

  const customFinding = result.findings.find((finding) => finding.raw === term);
  assert.equal(customFinding?.occurrences, 3);
  assert.equal(result.sanitizedConsole?.includes(term), false);
});

test("custom rules redact exact numeric JSON values", () => {
  const result = scanDiagnostics({
    consoleText: JSON.stringify({ orderNumber: 12345678, retryCount: 2 }),
    customTerms: ["12345678"],
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /12345678/);
  assert.match(result.sanitizedConsole ?? "", /\[SECRET_\d+\]/);
});

test("sensitive object keys are sanitized without overwriting collisions", () => {
  const result = scanDiagnostics({
    consoleText: JSON.stringify({
      "alice@example.com": "first",
      "ALICE@example.com": "second",
      password: "top-secret-password",
    }),
  });

  assert.equal(result.auditPassed, true);
  assert.doesNotMatch(result.sanitizedConsole ?? "", /alice@example\.com/i);
  const sanitized = JSON.parse(result.sanitizedConsole ?? "null") as Record<string, unknown>;
  assert.equal(sanitized["[EMAIL_1]"], "first");
  assert.equal(sanitized["[EMAIL_1]__2"], "second");
  assert.match(String(sanitized.password), /^\[SECRET_\d+\]$/);
});

test("high-confidence credential audit remains active", () => {
  const audit = auditSanitizedOutputs(["Authorization: Bearer abcdefghijklmnop"], []);
  assert.equal(audit.passed, false);
});
