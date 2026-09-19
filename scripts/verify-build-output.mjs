import { access, readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { basename, join, resolve } from "node:path";

const ROUTED_PREFIX = "__debugparcel_assets/";
const STATIC_PREFIX = `${ROUTED_PREFIX}_next/static/`;

function invariant(condition, message) {
  if (!condition) throw new Error(`Build verification failed: ${message}`);
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function listFiles(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await listFiles(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

async function readJson(path, label) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new Error(`Build verification failed: ${label} is missing or invalid.`, { cause: error });
  }
}

export async function verifyBuildOutput(root = process.cwd()) {
  const projectRoot = resolve(root);
  const clientDirectory = join(projectRoot, "dist", "client");
  const staticDirectory = join(clientDirectory, "_next", "static");
  invariant(await exists(staticDirectory), "dist/client/_next/static is missing.");

  const canonicalFiles = await listFiles(staticDirectory);
  invariant(canonicalFiles.length > 0, "dist/client/_next/static is empty.");
  invariant(
    canonicalFiles.some((path) => /^sanitize\.worker-.+\.js$/.test(basename(path))),
    "the sanitizer Web Worker was not emitted.",
  );
  invariant(
    !await exists(join(clientDirectory, ROUTED_PREFIX)),
    `dist/client/${ROUTED_PREFIX} must be removed after canonical assets are copied.`,
  );
  invariant(
    !await exists(join(clientDirectory, "_headers")),
    "dist/client/_headers must be absent so the Worker owns final response headers.",
  );

  const manifest = await readJson(
    join(clientDirectory, ".vite", "manifest.json"),
    "client Vite manifest",
  );
  const routedOutputs = [];
  for (const entry of Object.values(manifest)) {
    if (!entry || typeof entry !== "object") continue;
    if (typeof entry.file === "string") routedOutputs.push(entry.file);
    for (const field of ["css", "assets"]) {
      if (Array.isArray(entry[field])) {
        routedOutputs.push(...entry[field].filter((value) => typeof value === "string"));
      }
    }
  }
  invariant(routedOutputs.length > 0, "the client manifest has no emitted outputs.");
  for (const output of new Set(routedOutputs)) {
    invariant(
      output.startsWith(STATIC_PREFIX),
      `client manifest output ${JSON.stringify(output)} does not use ${STATIC_PREFIX}.`,
    );
    const canonicalPath = join(clientDirectory, output.slice(ROUTED_PREFIX.length));
    invariant(
      await exists(canonicalPath),
      `client manifest output ${JSON.stringify(output)} has no canonical backing file.`,
    );
  }

  const wrangler = await readJson(
    join(projectRoot, "dist", "server", "wrangler.json"),
    "server Wrangler configuration",
  );
  invariant(wrangler.assets?.binding === "ASSETS", "wrangler assets.binding must be ASSETS.");
  invariant(wrangler.assets?.directory === "../client", "wrangler assets.directory must be ../client.");
  invariant(
    !Object.prototype.hasOwnProperty.call(wrangler.assets ?? {}, "run_worker_first"),
    "wrangler assets.run_worker_first must stay unset.",
  );

  const sourceHosting = await readJson(
    join(projectRoot, ".openai", "hosting.json"),
    "source hosting configuration",
  );
  const builtHosting = await readJson(
    join(projectRoot, "dist", ".openai", "hosting.json"),
    "built hosting configuration",
  );
  invariant(
    typeof sourceHosting.project_id === "string" && sourceHosting.project_id.length > 0,
    "source hosting configuration has no project_id.",
  );
  invariant(
    builtHosting.project_id === sourceHosting.project_id,
    "built hosting configuration targets a different Sites project.",
  );

  const packageJson = await readJson(join(projectRoot, "package.json"), "package.json");
  const packageLock = await readJson(join(projectRoot, "package-lock.json"), "package-lock.json");
  const pageSource = await readFile(join(projectRoot, "app", "page.tsx"), "utf8");
  const appVersion = pageSource.match(/const APP_VERSION = "([^"]+)";/)?.[1];
  invariant(typeof packageJson.version === "string", "package.json has no version.");
  invariant(packageLock.version === packageJson.version, "package-lock.json version differs from package.json.");
  invariant(
    packageLock.packages?.[""]?.version === packageJson.version,
    "package-lock.json root package version differs from package.json.",
  );
  invariant(appVersion === packageJson.version, "APP_VERSION differs from package.json.");

  return {
    version: packageJson.version,
    projectId: sourceHosting.project_id,
    routedOutputs: new Set(routedOutputs).size,
    canonicalFiles: canonicalFiles.length,
  };
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  const summary = await verifyBuildOutput(process.argv[2] ?? process.cwd());
  console.log(
    `Verified DebugParcel v${summary.version} build output: ${summary.routedOutputs} routed outputs, ${summary.canonicalFiles} canonical files.`,
  );
}
