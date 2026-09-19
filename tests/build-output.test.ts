import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const verifierUrl = new URL("../scripts/verify-build-output.mjs", import.meta.url).href;
const { verifyBuildOutput } = await import(verifierUrl) as {
  verifyBuildOutput: (root: string) => Promise<unknown>;
};

async function writeJson(path: string, value: unknown) {
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, `${JSON.stringify(value)}\n`);
}

async function createValidBuildFixture() {
  const root = await mkdtemp(join(tmpdir(), "debugparcel-build-"));
  await mkdir(join(root, "app"), { recursive: true });
  await mkdir(join(root, "dist", "client", ".vite"), { recursive: true });
  await mkdir(join(root, "dist", "client", "_next", "static", "chunks"), { recursive: true });
  await mkdir(join(root, "dist", "server"), { recursive: true });
  await mkdir(join(root, "dist", ".openai"), { recursive: true });
  await mkdir(join(root, ".openai"), { recursive: true });

  await writeJson(join(root, "package.json"), { name: "debugparcel", version: "9.8.7" });
  await writeJson(join(root, "package-lock.json"), {
    name: "debugparcel",
    version: "9.8.7",
    packages: { "": { name: "debugparcel", version: "9.8.7" } },
  });
  await writeFile(join(root, "app", "page.tsx"), 'const APP_VERSION = "9.8.7";\n');
  await writeJson(join(root, ".openai", "hosting.json"), { project_id: "appgprj_fixture" });
  await writeJson(join(root, "dist", ".openai", "hosting.json"), { project_id: "appgprj_fixture" });
  await writeJson(join(root, "dist", "server", "wrangler.json"), {
    assets: { binding: "ASSETS", directory: "../client" },
  });
  await writeJson(join(root, "dist", "client", ".vite", "manifest.json"), {
    page: { file: "__debugparcel_assets/_next/static/chunks/page.js" },
    worker: { file: "__debugparcel_assets/_next/static/sanitize.worker-fixture.js" },
  });
  await writeFile(join(root, "dist", "client", "_next", "static", "chunks", "page.js"), "export {};\n");
  await writeFile(join(root, "dist", "client", "_next", "static", "sanitize.worker-fixture.js"), "self.onmessage = () => {};\n");
  return root;
}

test("build verifier accepts the canonical hosted artifact contract", async (context) => {
  const root = await createValidBuildFixture();
  context.after(() => rm(root, { recursive: true, force: true }));
  await assert.doesNotReject(() => verifyBuildOutput(root));
});

test("build verifier rejects run_worker_first regressions", async (context) => {
  const root = await createValidBuildFixture();
  context.after(() => rm(root, { recursive: true, force: true }));
  await writeJson(join(root, "dist", "server", "wrangler.json"), {
    assets: { binding: "ASSETS", directory: "../client", run_worker_first: true },
  });
  await assert.rejects(() => verifyBuildOutput(root), /run_worker_first/);
});

test("build verifier rejects manifest outputs without canonical backing files", async (context) => {
  const root = await createValidBuildFixture();
  context.after(() => rm(root, { recursive: true, force: true }));
  await writeJson(join(root, "dist", "client", ".vite", "manifest.json"), {
    page: { file: "__debugparcel_assets/_next/static/chunks/missing.js" },
  });
  await assert.rejects(() => verifyBuildOutput(root), /no canonical backing file/);
});

test("build verifier rejects a leftover routed asset directory", async (context) => {
  const root = await createValidBuildFixture();
  context.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "dist", "client", "__debugparcel_assets"), { recursive: true });
  await assert.rejects(() => verifyBuildOutput(root), /must be removed/);
});
