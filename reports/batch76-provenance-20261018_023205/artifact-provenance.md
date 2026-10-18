# Artifact Provenance & Fingerprint Audit

- **Status:** PASS
- **Generated (UTC):** 2026-10-18T02:32:05.444868+00:00
- **Artifacts audited:** 5
- **Valid JSON artifacts:** 5
- **Fingerprints recorded:** 5
- **Checks:** 15/15
- **Issues:** 0

## Artifact inventory

| Label | Exists | Valid JSON | Size (bytes) | SHA-256 |
|---|---:|---:|---:|---|
| triage | True | True | 1255 | `da196c3267dcc6941b7a97fae1d02503a616847cda28f5f56185a6f4c97f8f93` |

Path: `reports/batch65-evidence-triage-20261016_025025/evidence-gap-triage.json`
Report type: `historical_evidence_gap_triage`; status: `REVIEW_REQUIRED`
| matrix | True | True | 3609 | `7f6d014ae88bc179455db672d909b29011cfa83ea5d89adb3f92c8ceb80d739a` |

Path: `reports/batch66-evidence-coverage-20261016_025250/evidence-coverage-matrix.json`
Report type: `historical_evidence_coverage_matrix`; status: `REVIEW_REQUIRED`
| contract | True | True | 1929 | `0c96d3b76ad4f45f4a83fb19900664dfcb42918cd1b4af29818794f1b8e286b6` |

Path: `reports/batch73-contract-audit-20261018_022100/evidence-field-contract.json`
Report type: `evidence_field_contract_audit`; status: `PASS`
| gap_id_integrity | True | True | 1545 | `f85dbeeab7e54eb2947b8a948c58b42b71b61b193988a653742aa3ca0f70b73f` |

Path: `reports/batch74-gap-id-integrity-20261018_022431/gap-id-integrity.json`
Report type: `gap_id_integrity_audit`; status: `PASS`
| pipeline_integrity | True | True | 2491 | `5c13c5d0527d0a3b1bb11368e0b66ceadf5d4f7d3ffb6d9466e241af41579c6a` |

Path: `reports/batch75-pipeline-integrity-20261018_022824/evidence-pipeline-integrity.json`
Report type: `evidence_pipeline_integrity`; status: `PASS`

## Checks

- **PASS — triage_exists**: triage artifact exists.
- **PASS — triage_json_valid**: triage JSON is valid.
- **PASS — triage_sha256_available**: triage SHA-256 fingerprint recorded.
- **PASS — matrix_exists**: matrix artifact exists.
- **PASS — matrix_json_valid**: matrix JSON is valid.
- **PASS — matrix_sha256_available**: matrix SHA-256 fingerprint recorded.
- **PASS — contract_exists**: contract artifact exists.
- **PASS — contract_json_valid**: contract JSON is valid.
- **PASS — contract_sha256_available**: contract SHA-256 fingerprint recorded.
- **PASS — gap_id_integrity_exists**: gap_id_integrity artifact exists.
- **PASS — gap_id_integrity_json_valid**: gap_id_integrity JSON is valid.
- **PASS — gap_id_integrity_sha256_available**: gap_id_integrity SHA-256 fingerprint recorded.
- **PASS — pipeline_integrity_exists**: pipeline_integrity artifact exists.
- **PASS — pipeline_integrity_json_valid**: pipeline_integrity JSON is valid.
- **PASS — pipeline_integrity_sha256_available**: pipeline_integrity SHA-256 fingerprint recorded.

## Limitations

- A SHA-256 fingerprint identifies the bytes observed during this audit.
- A fingerprint alone does not prove who created an artifact or when it was originally created.
- This report does not compare against a previously trusted fingerprint manifest.
- Input artifacts are read-only; output files are written only to the requested output paths.

## Safety

- Read-only audit: `true`
- Source files modified: `false`
- System changes performed: `false`
- Automatic reclassification: `false`
- Automatic remediation: `false`
- Commands from artifacts executed: `false`
