# @tiny-owl-kit/tiny-owl-npm-scan

🦉 Scan your project's `package.json` for malicious npm packages from a curated CSV list.

## Features

- ✅ **Built-in malicious package database** - Scans using a curated list by default
- ✅ Scan both `dependencies` and `devDependencies`
- 🌐 Support for custom CSV files (local or remote URLs)
- 📦 Use as a CLI tool or programmatically in your code
- 🚀 Fast and lightweight
- 💯 TypeScript support

## Installation

### Global installation (CLI usage)

```bash
npm install -g @tiny-owl-kit/tiny-owl-npm-scan
```

### Local installation (programmatic usage)

```bash
npm install --save-dev @tiny-owl-kit/tiny-owl-npm-scan
```

## CLI Usage

**Important:** Run this command from the root directory of your project (where your `package.json` file is located).

```bash
cd path-to-your-project
```

### Quick scan with bundled malicious package list

```bash
tiny-owl-npm-scan
```

The tool includes a curated list of known malicious npm packages. Simply run the command without arguments to scan your project.

### Scan with a custom local CSV file

```bash
tiny-owl-npm-scan path/to/malicious-packages.csv
```

### Scan with a custom remote CSV file

```bash
tiny-owl-npm-scan https://example.com/malicious-packages.csv
```

### Using npx (no installation required)

```bash
# Scan with bundled list
npx @tiny-owl-kit/tiny-owl-npm-scan

# Scan with custom list
npx @tiny-owl-kit/tiny-owl-npm-scan path/to/malicious-packages.csv
```

## Programmatic Usage

```typescript
import { scanPackages } from "@tiny-owl-kit/tiny-owl-npm-scan";

// Scan with bundled malicious package list (recommended)
const result = await scanPackages();

console.log(`Found ${result.found.length} malicious packages:`);
result.found.forEach((pkg) => console.log(`- ${pkg}`));

// Scan with custom CSV file
const customResult = await scanPackages("path/to/malicious-packages.csv");

// Scan with custom options
const advancedResult = await scanPackages("https://example.com/list.csv", {
  packageJsonPath: "/path/to/package.json",
  includeDevDependencies: false,
});
```

## API

### `scanPackages(packageListSource?, options?)`

Main scanning function that checks if any packages from a malicious list are in your project.

#### Parameters

- **packageListSource** (`string`, optional): Path to CSV file or URL. If not provided, uses the bundled malicious package list.
- **options** (`ScanOptions`, optional):
  - `packageJsonPath` (`string`): Path to package.json file. Defaults to package.json in current working directory
  - `includeDevDependencies` (`boolean`): Whether to include devDependencies in scan. Defaults to `true`
  - `csvParser` (`function`): Custom CSV parser function

#### Returns

`Promise<ScanResult>`:

```typescript
{
  found: string[];        // List of malicious packages found
  totalScanned: number;   // Total number of packages scanned
  packageJsonPath: string; // Path to package.json that was scanned
}
```

### Utility Functions

#### `getDefaultCsvPath(): string`

Returns the path to the bundled malicious package list CSV file.

#### `isUrl(str: string): boolean`

Checks if a string is a valid URL.

#### `fetchUrl(url: string): Promise<string>`

Fetches content from a URL.

#### `parsePackageListCsv(csvContent: string): string[]`

Parses CSV content and extracts package names from the first column (skips header row).

#### `readDependencies(packageJsonPath: string, includeDevDependencies?: boolean): Record<string, string>`

Reads package.json and extracts dependencies.

## CSV Format

The CSV file should have package names in the first column:

```csv
package_name,description,severity
malicious-pkg-1,Description of issue,high
malicious-pkg-2,Another issue,medium
```

The first row (header) is automatically skipped.

## Exit Codes

When used as a CLI tool:

- **0**: No malicious packages found
- **1**: Malicious packages found or error occurred

## Examples

### Quick security scan (recommended)

```bash
# Use bundled malicious package list
tiny-owl-npm-scan
```

### Using with a custom GitHub URL

```bash
tiny-owl-npm-scan https://raw.githubusercontent.com/org/repo/main/malicious-packages.csv
```

### Integration in CI/CD

Add to your `package.json` scripts:

```json
{
  "scripts": {
    "security:scan": "tiny-owl-npm-scan"
  }
}
```

Then run in your CI pipeline:

```bash
npm run security:scan
```

### Custom scanning in Node.js

```typescript
import { scanPackages, ScanResult } from "@tiny-owl-kit/tiny-owl-npm-scan";

async function auditProject() {
  // Use bundled list (recommended)
  const result: ScanResult = await scanPackages();

  if (result.found.length > 0) {
    console.error("Security Alert!");
    result.found.forEach((pkg) => {
      console.error(`Malicious package detected: ${pkg}`);
    });
    process.exit(1);
  }
}

auditProject();
```

## Development

### Build

```bash
npm run build
```

### Test

```bash
npm test
```

### Run tests in watch mode

```bash
npm run test:watch
```

### Coverage

```bash
npm run test:coverage
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT

## Security

If you discover a security vulnerability, please email [your-email@example.com].

## Acknowledgments

Built with 🦉 by the Tiny Owl team.
