import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { createReadStream } from "node:fs";
import path from "node:path";

const parseArgs = (argv) => {
  const args = {};

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      continue;
    }

    const key = token.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for --${key}`);
    }

    args[key] = value;
    index += 1;
  }

  return args;
};

const sha256File = async (filePath) => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest("hex");
};

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  if (!args.artifact?.trim() || !args.output?.trim() || !args.version?.trim()) throw new Error("Usage: --artifact <file> --output <file> --version <tag>");
  const artifactPath = path.resolve(args.artifact || "");
  const outputPath = path.resolve(args.output || "");
  const identity = file => process.platform === 'win32' ? file.toLowerCase() : file;
  if (identity(artifactPath) === identity(outputPath)) throw new Error("Manifest output must not overwrite its artifact");
  if (!(await fs.lstat(artifactPath)).isFile()) throw new Error("Distro artifact must be a regular file");
  const version = (args.version || "").trim();
  const publishedAt = (args["published-at"] || new Date().toISOString()).trim();
  const publicArtifactPath = (args["artifact-path"] || "/distro/404-distro.tar.gz").trim();
  if (!Number.isFinite(Date.parse(publishedAt)) || !publicArtifactPath.startsWith("/") || publicArtifactPath.startsWith("//")) throw new Error("Invalid publication timestamp or artifact path");

  if (!artifactPath || !outputPath || !version) {
    throw new Error(
      "Usage: node .github/scripts/build-distro-release-manifest.mjs --artifact <file> --output <file> --version <tag> [--artifact-path /distro/404-distro.tar.gz] [--published-at <ISO-8601>]",
    );
  }

  const manifest = {
    version,
    sha256: await sha256File(artifactPath),
    artifact_path: publicArtifactPath,
    published_at: publishedAt,
  };

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});