type ZipInput = {
  name: string;
  data: Blob | Uint8Array | string;
};

type PreparedFile = {
  name: Uint8Array;
  data: Uint8Array;
  crc: number;
  offset: number;
};

const encoder = new TextEncoder();

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let value = n;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[n] = value >>> 0;
  }
  return table;
})();

function crc32(data: Uint8Array) {
  let crc = 0xffffffff;
  for (const byte of data) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date: Date) {
  const year = Math.max(1980, date.getFullYear());
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const day = (year - 1980) << 9 | (date.getMonth() + 1) << 5 | date.getDate();
  return { time, day };
}

function header(size: number) {
  return new Uint8Array(size);
}

function blobPart(data: Uint8Array) {
  return data.slice().buffer as ArrayBuffer;
}

function write16(view: DataView, offset: number, value: number) {
  view.setUint16(offset, value, true);
}

function write32(view: DataView, offset: number, value: number) {
  view.setUint32(offset, value >>> 0, true);
}

async function asBytes(data: ZipInput["data"]) {
  if (typeof data === "string") return encoder.encode(data);
  if (data instanceof Uint8Array) return data;
  return new Uint8Array(await data.arrayBuffer());
}

export async function makeZip(files: ZipInput[]) {
  const prepared: PreparedFile[] = [];
  let offset = 0;
  const now = dosDateTime(new Date());
  const chunks: BlobPart[] = [];

  for (const file of files) {
    const name = encoder.encode(file.name);
    const data = await asBytes(file.data);
    const crc = crc32(data);
    const local = header(30);
    const view = new DataView(local.buffer);
    write32(view, 0, 0x04034b50);
    write16(view, 4, 20);
    write16(view, 6, 0x0800);
    write16(view, 8, 0);
    write16(view, 10, now.time);
    write16(view, 12, now.day);
    write32(view, 14, crc);
    write32(view, 18, data.length);
    write32(view, 22, data.length);
    write16(view, 26, name.length);
    write16(view, 28, 0);
    chunks.push(blobPart(local), blobPart(name), blobPart(data));
    prepared.push({ name, data, crc, offset });
    offset += local.length + name.length + data.length;
  }

  const centralOffset = offset;
  let centralSize = 0;
  for (const file of prepared) {
    const central = header(46);
    const view = new DataView(central.buffer);
    write32(view, 0, 0x02014b50);
    write16(view, 4, 20);
    write16(view, 6, 20);
    write16(view, 8, 0x0800);
    write16(view, 10, 0);
    write16(view, 12, now.time);
    write16(view, 14, now.day);
    write32(view, 16, file.crc);
    write32(view, 20, file.data.length);
    write32(view, 24, file.data.length);
    write16(view, 28, file.name.length);
    write16(view, 30, 0);
    write16(view, 32, 0);
    write16(view, 34, 0);
    write16(view, 36, 0);
    write32(view, 38, 0);
    write32(view, 42, file.offset);
    chunks.push(blobPart(central), blobPart(file.name));
    centralSize += central.length + file.name.length;
  }

  const end = header(22);
  const view = new DataView(end.buffer);
  write32(view, 0, 0x06054b50);
  write16(view, 4, 0);
  write16(view, 6, 0);
  write16(view, 8, prepared.length);
  write16(view, 10, prepared.length);
  write32(view, 12, centralSize);
  write32(view, 16, centralOffset);
  write16(view, 20, 0);
  chunks.push(blobPart(end));

  return new Blob(chunks, { type: "application/zip" });
}

export async function sha256(data: Blob | string) {
  const bytes = typeof data === "string" ? encoder.encode(data) : await data.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
