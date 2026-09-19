import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readExecutionProfile } from "./execution-profile.mjs";

const [command, ...args] = process.argv.slice(2);
if (!["dev", "build"].includes(command)) throw new Error("Expected dev or build.");
const managedLinux = readExecutionProfile() === "managed-linux";

if (managedLinux && command === "build") {
  const result = spawnSync("bash", [
    fileURLToPath(new URL("./build-verified.sh", import.meta.url)), ...args,
  ], { stdio: "inherit" });
  if (result.error) throw result.error;
  process.exit(result.status ?? 1);
}

const cli = new URL(managedLinux
  ? "../node_modules/vite/bin/vite.js"
  : "../node_modules/vinext/dist/cli.js", import.meta.url);
if (command === "build") {
  const result = spawnSync(process.execPath, [fileURLToPath(cli), command, ...args], {
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  const { verifyBuildOutput } = await import("./verify-build-output.mjs");
  const summary = await verifyBuildOutput();
  console.log(
    `Verified DebugParcel v${summary.version} build output: ${summary.routedOutputs} routed outputs, ${summary.canonicalFiles} canonical files.`,
  );
} else {
  // Import dev in this process so the preview owner retains its PID and signals.
  process.argv = [process.execPath, fileURLToPath(cli), command,
    ...(!managedLinux ? ["--port", "5173"] : []), ...args];
  await import(cli.href);
}
