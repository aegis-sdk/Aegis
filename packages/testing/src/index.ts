/**
 * @aegis-sdk/testing — Red team testing tools for Aegis.
 *
 * Provides attack suites, payload generators, and testing utilities
 * for validating prompt injection defenses.
 *
 * @example
 * ```ts
 * import { RedTeamScanner } from '@aegis-sdk/testing';
 *
 * const scanner = new RedTeamScanner();
 * const results = await scanner.run(aegis, {
 *   suites: ['instruction-override', 'encoding-bypass', 'role-manipulation'],
 * });
 * ```
 */

export { RedTeamScanner } from "./scanner.js";
export {
  ATTACK_SUITES,
  getAllSuites,
  getSuiteById,
  getSuitesByThreatCategory,
  getAllPayloads,
  type AttackSuite,
  type AttackPayload,
} from "./suites/index.js";
export { PayloadGenerator } from "./generators/index.js";
