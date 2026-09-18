import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

const zipModuleUrl = new URL("../lib/zip.ts", import.meta.url).href;
const { makeZip, sha256 } = await import(zipModuleUrl) as typeof import("../lib/zip");

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const ZIP_LOCAL_FILE = 0x04034b50;
const ZIP_CENTRAL_FILE = 0x02014b50;
const ZIP_END = 0x06054b50;
const UTF8_FLAG = 0x0800;

function crc32(data: Uint8Array) {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function findEndRecord(bytes: Uint8Array) {
  const minimumOffset = Math.max(0, bytes.length - 22 - 0xffff);
  for (let offset = bytes.length - 22; offset >= minimumOffset; offset -= 1) {
    const view = new DataView(bytes.buffer, bytes.byteOffset + offset, bytes.length - offset);
    if (view.getUint32(0, true) === ZIP_END) return offset;
  }
  throw new Error("ZIP end-of-central-directory record was not found.");
}

async function toBytes(value: string | Blob | Uint8Array) {
  if (typeof value === "string") return encoder.encode(value);
  if (value instanceof Uint8Array) return value;
  return new Uint8Array(await value.arrayBuffer());
}

test("makeZip writes safe fixed entries with coherent headers, CRCs, sizes, and offsets", async () => {
  const files: Array<{ name: string; data: string | Blob | Uint8Array }> = [
    { name: "report.md", data: "# Safe debug report\n" },
    { name: "network.sanitized.har", data: '{"log":{"entries":[]}}' },
    { name: "console.sanitized.json", data: new Blob(['[{"level":"error"}]']) },
    { name: "screenshot.redacted.png", data: new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]) },
    { name: "manifest.json", data: '{"schemaVersion":1}' },
  ];
  const expectedNames = files.map((file) => file.name);
  const expectedData = new Map(
    await Promise.all(files.map(async (file) => [file.name, await toBytes(file.data)] as const)),
  );

  const blob = await makeZip(files);
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const endOffset = findEndRecord(bytes);
  const end = new DataView(bytes.buffer, bytes.byteOffset + endOffset, 22);

  assert.equal(end.getUint16(4, true), 0, "archive must start on disk zero");
  assert.equal(end.getUint16(6, true), 0, "central directory must remain on disk zero");
  assert.equal(end.getUint16(8, true), files.length);
  assert.equal(end.getUint16(10, true), files.length);
  assert.equal(end.getUint16(20, true), 0, "archive must not append an unexpected comment");

  const centralSize = end.getUint32(12, true);
  const centralOffset = end.getUint32(16, true);
  assert.ok(centralOffset > 0 && centralOffset < endOffset);
  assert.equal(centralOffset + centralSize, endOffset);

  const observedNames: string[] = [];
  let centralCursor = centralOffset;
  let previousLocalEnd = 0;
  for (let index = 0; index < files.length; index += 1) {
    const central = new DataView(bytes.buffer, bytes.byteOffset + centralCursor, endOffset - centralCursor);
    assert.equal(central.getUint32(0, true), ZIP_CENTRAL_FILE);
    assert.equal(central.getUint16(8, true), UTF8_FLAG);
    assert.equal(central.getUint16(10, true), 0, "fixtures should use the stored method");

    const crc = central.getUint32(16, true);
    const compressedSize = central.getUint32(20, true);
    const uncompressedSize = central.getUint32(24, true);
    const nameLength = central.getUint16(28, true);
    const extraLength = central.getUint16(30, true);
    const commentLength = central.getUint16(32, true);
    const localOffset = central.getUint32(42, true);
    const nameStart = centralCursor + 46;
    const name = decoder.decode(bytes.subarray(nameStart, nameStart + nameLength));
    observedNames.push(name);

    assert.equal(name, expectedNames[index]);
    assert.ok(!name.startsWith("/") && !name.startsWith("\\"));
    assert.ok(!name.split(/[\\/]/).includes(".."));
    assert.equal(compressedSize, uncompressedSize);
    assert.ok(localOffset >= previousLocalEnd && localOffset < centralOffset);

    const local = new DataView(bytes.buffer, bytes.byteOffset + localOffset, centralOffset - localOffset);
    assert.equal(local.getUint32(0, true), ZIP_LOCAL_FILE);
    assert.equal(local.getUint16(6, true), UTF8_FLAG);
    assert.equal(local.getUint16(8, true), 0);
    assert.equal(local.getUint32(14, true), crc);
    assert.equal(local.getUint32(18, true), compressedSize);
    assert.equal(local.getUint32(22, true), uncompressedSize);

    const localNameLength = local.getUint16(26, true);
    const localExtraLength = local.getUint16(28, true);
    const localNameStart = localOffset + 30;
    assert.equal(decoder.decode(bytes.subarray(localNameStart, localNameStart + localNameLength)), name);

    const dataStart = localNameStart + localNameLength + localExtraLength;
    const dataEnd = dataStart + compressedSize;
    assert.ok(dataEnd <= centralOffset);
    const payload = bytes.subarray(dataStart, dataEnd);
    assert.deepEqual(payload, expectedData.get(name));
    assert.equal(crc32(payload), crc);
    previousLocalEnd = dataEnd;

    centralCursor = nameStart + nameLength + extraLength + commentLength;
  }

  assert.deepEqual(observedNames, expectedNames);
  assert.equal(previousLocalEnd, centralOffset, "local records must end where the central directory begins");
  assert.equal(centralCursor, endOffset, "central records must fill the declared central-directory size");
});

test("sha256 returns the same digest for equivalent string and Blob inputs", async () => {
  const fixture = "DebugParcel hash fixture";
  const fromString = await sha256(fixture);
  const fromBlob = await sha256(new Blob([fixture], { type: "text/plain" }));
  const expected = createHash("sha256").update(fixture, "utf8").digest("hex");

  assert.equal(fromString, fromBlob);
  assert.equal(fromString, expected);
  assert.match(fromString, /^[a-f0-9]{64}$/);
});
