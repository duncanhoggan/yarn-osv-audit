import { describe, expect, it } from "vitest";
import { calculateCvssScore, cvssToSeverity, severityFromString } from "../src/cvss.js";

describe("calculateCvssScore", () => {
  it("calculates CVSS:3.1 score for a high severity vector", () => {
    // AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H -> 7.5
    const score = calculateCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
    expect(score).toBe(7.5);
  });

  it("calculates CVSS:3.1 score for a critical severity vector", () => {
    // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
    const score = calculateCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(score).toBe(9.8);
  });

  it("calculates CVSS:3.0 score", () => {
    const score = calculateCvssScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(score).toBe(9.8);
  });

  it("calculates score with changed scope", () => {
    // AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H -> 10.0
    const score = calculateCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    expect(score).toBe(10.0);
  });

  it("returns 0 for no-impact vector", () => {
    // AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N -> 0.0
    const score = calculateCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
    expect(score).toBe(0);
  });

  it("calculates a low severity score", () => {
    // AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N -> 1.8
    const score = calculateCvssScore("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N");
    expect(score).toBe(1.8);
  });

  it("calculates a moderate severity score", () => {
    // AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N -> 4.3
    const score = calculateCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
    expect(score).toBe(4.3);
  });

  it("returns null for invalid vectors", () => {
    expect(calculateCvssScore("not-a-vector")).toBeNull();
    expect(calculateCvssScore("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")).toBeNull();
    expect(calculateCvssScore("CVSS:3.1/AV:N")).toBeNull();
  });
});

describe("cvssToSeverity", () => {
  it("maps scores to correct severity levels", () => {
    expect(cvssToSeverity(0)).toBe("LOW");
    expect(cvssToSeverity(2.0)).toBe("LOW");
    expect(cvssToSeverity(3.9)).toBe("LOW");
    expect(cvssToSeverity(4.0)).toBe("MODERATE");
    expect(cvssToSeverity(6.9)).toBe("MODERATE");
    expect(cvssToSeverity(7.0)).toBe("HIGH");
    expect(cvssToSeverity(8.9)).toBe("HIGH");
    expect(cvssToSeverity(9.0)).toBe("CRITICAL");
    expect(cvssToSeverity(10.0)).toBe("CRITICAL");
  });
});

describe("severityFromString", () => {
  it("maps string severity to level and score", () => {
    expect(severityFromString("CRITICAL")).toEqual({ level: "CRITICAL", score: 9.5 });
    expect(severityFromString("HIGH")).toEqual({ level: "HIGH", score: 7.5 });
    expect(severityFromString("MEDIUM")).toEqual({ level: "MODERATE", score: 5.0 });
    expect(severityFromString("MODERATE")).toEqual({ level: "MODERATE", score: 5.0 });
    expect(severityFromString("LOW")).toEqual({ level: "LOW", score: 2.0 });
  });
});
