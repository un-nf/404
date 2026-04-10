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

const walk = async (rootDirectory) => {
  const entries = await fs.readdir(rootDirectory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(rootDirectory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walk(fullPath)));
    } else {
      files.push(fullPath);
    }
  }

  return files;
};

const sha256File = async (filePath) => {
  const contents = await fs.readFile(filePath);
  return createHash("sha256").update(contents).digest("hex");
};

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  const inputRoot = path.resolve(args.input || "");
  const outputPath = path.resolve(args.output || "");
  const version = (args.version || "").trim();

  if (!inputRoot || !outputPath || !version) {
    throw new Error(
      "Usage: node .github/scripts/build-static-release-manifest.mjs --input <dir> --output <file> --version <tag>",
    );
  }

  const files = await walk(inputRoot);
  const artifacts = [];

  for (const filePath of files) {
    const fileName = path.basename(filePath);
    if (
      fileName === "static_proxy-release-manifest.json" ||
      fileName === "static_proxy-release-manifest.json.sig" ||
      fileName === "static_proxy-release-manifest.json.pem"
    ) {
      continue;
    }

    artifacts.push({
      name: fileName,
      sha256: await sha256File(filePath),
    });
  }

  artifacts.sort((left, right) => left.name.localeCompare(right.name));

  if (artifacts.length === 0) {
    throw new Error(`No release artifacts were found in ${inputRoot}`);
  }

  const manifest = {
    version,
    artifacts,
  };

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});