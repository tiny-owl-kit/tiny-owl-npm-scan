/**
 * tiny-owl-npm-scan
 * Scan your project's package.json for malicious packages from a CSV list
 */

import * as fs from "fs";
import * as path from "path";
import * as https from "https";
import * as http from "http";

export interface ScanOptions {
  /** Path to package.json file. Defaults to package.json in current working directory */
  packageJsonPath?: string;
  /** Whether to include devDependencies in scan. Defaults to true */
  includeDevDependencies?: boolean;
  /** Custom CSV parser function */
  csvParser?: (content: string) => string[];
}

export interface ScanResult {
  /** List of malicious packages found in the project */
  found: string[];
  /** Total number of packages scanned */
  totalScanned: number;
  /** Path to package.json that was scanned */
  packageJsonPath: string;
}

/**
 * Fetches content from a URL
 */
export const fetchUrl = (url: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    const protocol = url.startsWith("https") ? https : http;
    protocol
      .get(url, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve(data));
      })
      .on("error", reject);
  });
};

/**
 * Checks if a string is a valid URL
 */
export const isUrl = (str: string): boolean => {
  return str.startsWith("http://") || str.startsWith("https://");
};

/**
 * Gets the default package list CSV path bundled with the package
 */
export const getDefaultCsvPath = (): string => {
  return path.join(__dirname, "..", "list", "package-list.csv");
};

/**
 * Parses CSV content and extracts package names from the first column
 * Skips the header row
 */
export const parsePackageListCsv = (csvContent: string): string[] => {
  return csvContent
    .split("\n")
    .slice(1) // Skip the header row
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      // Extract package name from CSV (first column)
      const columns = line.split(",");
      return columns[0]?.trim() || "";
    })
    .filter(Boolean);
};

/**
 * Reads package.json and extracts dependencies
 */
export const readDependencies = (
  packageJsonPath: string,
  includeDevDependencies: boolean = true
): Record<string, string> => {
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
  const dependencies = { ...packageJson.dependencies };

  if (includeDevDependencies && packageJson.devDependencies) {
    Object.assign(dependencies, packageJson.devDependencies);
  }

  return dependencies;
};

/**
 * Main scanning function - checks if any packages from the malicious list are in the project
 * @param packageListSource - Path to CSV file or URL. If not provided, uses the bundled malicious package list
 * @param options - Scanning options
 * @returns Scan results with found malicious packages
 */
export const scanPackages = async (
  packageListSource?: string,
  options: ScanOptions = {}
): Promise<ScanResult> => {
  const {
    packageJsonPath = path.resolve(process.cwd(), "package.json"),
    includeDevDependencies = true,
    csvParser = parsePackageListCsv,
  } = options;

  // Use default CSV if not provided
  const csvPath = packageListSource || getDefaultCsvPath();

  // Read CSV file from URL or local file
  let csvContent: string;

  if (isUrl(csvPath)) {
    csvContent = await fetchUrl(csvPath);
  } else {
    csvContent = fs.readFileSync(csvPath, "utf-8");
  }

  // Parse CSV and extract package names
  const packageList = csvParser(csvContent);

  // Read dependencies from package.json
  const dependencies = readDependencies(
    packageJsonPath,
    includeDevDependencies
  );

  // Find matching packages
  const found: string[] = [];
  for (const pkg of packageList) {
    if (dependencies[pkg]) {
      found.push(pkg);
    }
  }

  return {
    found,
    totalScanned: packageList.length,
    packageJsonPath,
  };
};

/**
 * CLI entry point
 */
export const runCli = async (args: string[]): Promise<void> => {
  const packageListPath = args[0];

  try {
    if (packageListPath) {
      if (isUrl(packageListPath)) {
        console.log(`Fetching package list from URL: ${packageListPath}`);
      } else {
        console.log(`Using custom package list: ${packageListPath}`);
      }
    } else {
      console.log("Using bundled malicious package list...");
    }

    const result = await scanPackages(packageListPath);

    if (result.found.length) {
      console.log(
        `\n⚠️  WARNING: ${result.found.length} malicious package(s) found in your project:\n`
      );
      result.found.forEach((pkg) => console.log(`  ❌ ${pkg}`));
      console.log(
        `\nScanned ${result.totalScanned} packages from the malicious list.`
      );
      process.exit(1);
    } else {
      console.log("✅ No malicious packages found in this project.");
      console.log(
        `Scanned ${result.totalScanned} packages from the malicious list.`
      );
      process.exit(0);
    }
  } catch (error) {
    console.error(
      "Error:",
      error instanceof Error ? error.message : String(error)
    );
    process.exit(1);
  }
};
