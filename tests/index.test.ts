import * as fs from "fs";
import * as path from "path";
import {
  isUrl,
  parsePackageListCsv,
  readDependencies,
  scanPackages,
  fetchUrl,
  getDefaultCsvPath,
} from "../src/index";

// Mock data
const mockPackageJson = {
  dependencies: {
    express: "^4.18.0",
    lodash: "^4.17.21",
    "malicious-pkg": "^1.0.0",
  },
  devDependencies: {
    jest: "^29.0.0",
    "evil-pkg": "^2.0.0",
  },
};

const mockCsv = `package_name,description,severity
malicious-pkg,Description of issue,high
evil-pkg,Another issue,medium
harmless-pkg,Not in project,low`;

describe("tiny-owl-npm-scan", () => {
  describe("isUrl", () => {
    it("should return true for valid HTTP URLs", () => {
      expect(isUrl("http://example.com")).toBe(true);
    });

    it("should return true for valid HTTPS URLs", () => {
      expect(isUrl("https://example.com")).toBe(true);
    });

    it("should return false for file paths", () => {
      expect(isUrl("/path/to/file.csv")).toBe(false);
      expect(isUrl("path/to/file.csv")).toBe(false);
    });

    it("should return false for other protocols", () => {
      expect(isUrl("ftp://example.com")).toBe(false);
    });
  });

  describe("parsePackageListCsv", () => {
    it("should parse CSV and extract package names", () => {
      const result = parsePackageListCsv(mockCsv);
      expect(result).toEqual(["malicious-pkg", "evil-pkg", "harmless-pkg"]);
    });

    it("should skip header row", () => {
      const result = parsePackageListCsv(mockCsv);
      expect(result).not.toContain("package_name");
    });

    it("should handle empty lines", () => {
      const csvWithEmptyLines = `package_name,description
pkg1,desc1

pkg2,desc2


pkg3,desc3`;
      const result = parsePackageListCsv(csvWithEmptyLines);
      expect(result).toEqual(["pkg1", "pkg2", "pkg3"]);
    });

    it("should handle CSV with only headers", () => {
      const result = parsePackageListCsv("package_name,description");
      expect(result).toEqual([]);
    });
  });

  describe("getDefaultCsvPath", () => {
    it("should return a valid path to the default CSV", () => {
      const defaultPath = getDefaultCsvPath();
      expect(defaultPath).toContain("list");
      expect(defaultPath).toContain("package-list.csv");
    });
  });

  describe("readDependencies", () => {
    let tempPackageJsonPath: string;

    beforeEach(() => {
      tempPackageJsonPath = path.join(__dirname, "temp-package.json");
      fs.writeFileSync(tempPackageJsonPath, JSON.stringify(mockPackageJson));
    });

    afterEach(() => {
      if (fs.existsSync(tempPackageJsonPath)) {
        fs.unlinkSync(tempPackageJsonPath);
      }
    });

    it("should read both dependencies and devDependencies by default", () => {
      const deps = readDependencies(tempPackageJsonPath);
      expect(deps).toEqual({
        express: "^4.18.0",
        lodash: "^4.17.21",
        "malicious-pkg": "^1.0.0",
        jest: "^29.0.0",
        "evil-pkg": "^2.0.0",
      });
    });

    it("should read only dependencies when includeDevDependencies is false", () => {
      const deps = readDependencies(tempPackageJsonPath, false);
      expect(deps).toEqual({
        express: "^4.18.0",
        lodash: "^4.17.21",
        "malicious-pkg": "^1.0.0",
      });
    });

    it("should handle package.json without devDependencies", () => {
      const minimalPackageJson = {
        dependencies: { express: "^4.18.0" },
      };
      fs.writeFileSync(tempPackageJsonPath, JSON.stringify(minimalPackageJson));
      const deps = readDependencies(tempPackageJsonPath);
      expect(deps).toEqual({ express: "^4.18.0" });
    });
  });

  describe("scanPackages", () => {
    let tempPackageJsonPath: string;
    let tempCsvPath: string;

    beforeEach(() => {
      tempPackageJsonPath = path.join(__dirname, "temp-package.json");
      tempCsvPath = path.join(__dirname, "temp-list.csv");
      fs.writeFileSync(tempPackageJsonPath, JSON.stringify(mockPackageJson));
      fs.writeFileSync(tempCsvPath, mockCsv);
    });

    afterEach(() => {
      if (fs.existsSync(tempPackageJsonPath)) {
        fs.unlinkSync(tempPackageJsonPath);
      }
      if (fs.existsSync(tempCsvPath)) {
        fs.unlinkSync(tempCsvPath);
      }
    });

    it("should find malicious packages in project", async () => {
      const result = await scanPackages(tempCsvPath, {
        packageJsonPath: tempPackageJsonPath,
      });

      expect(result.found).toContain("malicious-pkg");
      expect(result.found).toContain("evil-pkg");
      expect(result.found).toHaveLength(2);
      expect(result.totalScanned).toBe(3);
    });

    it("should not include devDependencies when option is false", async () => {
      const result = await scanPackages(tempCsvPath, {
        packageJsonPath: tempPackageJsonPath,
        includeDevDependencies: false,
      });

      expect(result.found).toContain("malicious-pkg");
      expect(result.found).not.toContain("evil-pkg");
      expect(result.found).toHaveLength(1);
    });

    it("should return empty array when no malicious packages found", async () => {
      const cleanCsv = `package_name,description
safe-pkg-1,Safe package
safe-pkg-2,Another safe package`;
      fs.writeFileSync(tempCsvPath, cleanCsv);

      const result = await scanPackages(tempCsvPath, {
        packageJsonPath: tempPackageJsonPath,
      });

      expect(result.found).toEqual([]);
      expect(result.totalScanned).toBe(2);
    });

    it("should work with custom CSV parser", async () => {
      const customParser = (content: string) => {
        return content.split("\n").filter((line) => line.includes("evil"));
      };

      const result = await scanPackages(tempCsvPath, {
        packageJsonPath: tempPackageJsonPath,
        csvParser: customParser,
      });

      // Custom parser should only find 'evil-pkg' line
      expect(result.totalScanned).toBeGreaterThan(0);
    });

    it("should use bundled CSV when no packageListSource provided", async () => {
      // This test verifies the default behavior
      const result = await scanPackages(undefined, {
        packageJsonPath: tempPackageJsonPath,
      });

      // The bundled CSV has many packages, so totalScanned should be high
      expect(result.totalScanned).toBeGreaterThan(100);
      expect(result.found).toBeDefined();
      expect(Array.isArray(result.found)).toBe(true);
    });
  });

  describe("fetchUrl", () => {
    // Note: These tests would require mocking http/https modules
    // or using a test server. For now, we'll test the basic structure.

    it("should be a function", () => {
      expect(typeof fetchUrl).toBe("function");
    });

    it("should return a Promise", () => {
      const result = fetchUrl("http://example.com");
      expect(result).toBeInstanceOf(Promise);
      // Prevent the real network call from surfacing as an unhandled rejection
      result.catch(() => undefined);
    });
  });
});
