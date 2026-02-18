/**
 * @aegis-sdk/testing — Red team testing tools for Aegis.
 *
 * Provides attack suites, payload generators, testing utilities,
 * and Promptfoo compatibility for validating prompt injection defenses.
 *
 * @example
 * ```ts
 * import { RedTeamScanner } from '@aegis-sdk/testing';
 *
 * const scanner = new RedTeamScanner();
 * const results = await scanner.run(aegis, {
 *   suites: ['direct-injection', 'encoding-bypass', 'role-manipulation'],
 *   concurrency: 20,
 * });
 * console.log(scanner.generateReport(results));
 * ```
 */

export { RedTeamScanner } from "./scanner.js";
export type { RedTeamResult, RedTeamOptions, SuiteResult, PayloadResult } from "./scanner.js";
export {
  ATTACK_SUITES,
  getAllSuites,
  getSuiteById,
  getSuitesByThreatCategory,
  getAllPayloads,
  type AttackSuite,
  type AttackPayload,
} from "./suites/index.js";
export {
  PayloadGenerator,
  generateFuzzPayloads,
  type GenerateFuzzPayloadsOptions,
  type FuzzEncoding,
} from "./generators/index.js";
export {
  generatePromptfooConfig,
  createPromptfooAssertion,
  type PromptfooConfig,
  type PromptfooTestCase,
  type PromptfooAssert,
  type PromptfooAssertion,
  type GeneratePromptfooConfigOptions,
} from "./promptfoo.js";
