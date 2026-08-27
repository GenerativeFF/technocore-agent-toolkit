"""Technocore Protocol Test Vectors Format (v0.4.0)

This document specifies the schema and expected content for test vector
files used by the ``technocore-agent-toolkit`` project. These vectors
are crucial for ensuring interoperability and verifying correctness of
protocol implementations.

## Overview

Test vectors are stored in JSON format within the ``vectors/`` directory.
Each file typically corresponds to a specific module or feature being
tested (e.g., ``nonce_cases.json``, ``scanner_cases.json``).

## Schema Versioning

Each vector file MUST include a ``schema_version`` field at the top level.
This allows for future-incompatible changes to the schema while maintaining
backward compatibility where possible.

## File Structure

All vector files share a common top-level structure:

- ``schema_version`` (integer): The version of the schema this file adheres to.
- ``description`` (string): A human-readable description of the vector set's purpose.
- ``notes`` (list of strings): Optional supplementary notes or caveats about the vectors.
- ``cases`` (list of objects): The core data, where each object represents a single test case.

## Test Case Structure (Module-Specific)

The structure of objects within the ``cases`` list varies depending on the
module being tested. Below are the formats for the current nonce and scanner
vectors.

### Nonce Vectors (`vectors/nonce_cases.json`)

Each case object tests the ``NonceChecker`` and includes the following fields:

- ``name`` (string): A short, descriptive name for the test case.
- ``did`` (string): A placeholder DID string used for testing isolation.
- ``room`` (string): The room identifier.
- ``nonce`` (string): The nonce string to be tested.
- ``prior_nonces`` (list of lists of strings, optional): A list of prior nonces that should have been processed successfully *before* the current nonce is checked. Each inner list represents a `[did, room, nonce]` tuple.
- ``expect_valid`` (boolean): Whether the nonce check is expected to pass (`True`) or fail (`False`).
- ``expect_reason_contains`` (string | null, optional): If `expect_valid` is `False`, this field specifies a case-insensitive substring that *must* be present in the `reason` returned by the `NonceChecker`. If `null` or omitted, no specific reason is asserted.

### Scanner Vectors (`vectors/scanner_cases.json`)

Each case object tests the ``scan`` function and includes the following fields:

- ``name`` (string): A short, descriptive name for the test case.
- ``text`` (string): The input text to be scanned. May contain special characters (e.g., \\uXXXX escapes for hidden/control characters).
- ``expect_safe`` (boolean): Whether the text is expected to be classified as safe overall (i.e., all findings are 'info' severity).
- ``expect_categories`` (list of strings, optional): A list of categories that *must* be detected in the scan results. If empty or omitted, the presence of any specific category is not asserted beyond the `expect_min_*_count` fields.
- ``expect_min_high_count`` (integer): The minimum number of 'high' severity findings expected. Defaults to 0.
- ``expect_min_warn_count`` (integer): The minimum number of 'warn' severity findings expected. Defaults to 0.

## Notes on Vector Content

- **Sanitization**: All vectors are synthetic and contain no live data, private keys, credentials, real URLs, or executable paths. They are designed solely to test the pattern matching and logic of the respective modules.
- **Determinism**: Vector generation scripts are designed to produce byte-identical output files when re-run, ensuring that the test vectors themselves are stable.
- **Extensibility**: When adding new test cases or modules, please adhere to the existing schema and conventions. Update ``schema_version`` only for backward-incompatible changes.
