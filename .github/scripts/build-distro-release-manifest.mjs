import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
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
  const contents = await fs.readFile(filePath);
  return createHash("sha256").update(contents).digest("hex");
};

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  const artifactPath = path.resolve(args.artifact || "");
  const outputPath = path.resolve(args.output || "");
  const version = (args.version || "").trim();
  const publishedAt = (args["published-at"] || new Date().toISOString()).trim();
  const publicArtifactPath = (args["artifact-path"] || "/distro/404-distro.tar.gz").trim();

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