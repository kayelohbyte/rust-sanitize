# Detection Quality Scorecard

Generated from [`tests/detection_corpus/`](../tests/detection_corpus/) by
`cargo test --test detection_quality_tests regenerate_scorecard -- --ignored`.
Do not edit by hand — CI fails if this file is stale.

**Contract:** every positive below is detected by the zero-config built-in
pattern set (recall 1.0 on the corpus), every negative passes through
unchanged, and positives survive chunk-boundary padding. Corpus cases are
synthetic but format-valid; shapes adapted from public gitleaks/trufflehog
rule tests (MIT) and provider format documentation.

| Corpus file | Pattern | Positives |
|-------------|---------|-----------|
| cloud-keys | `anthropic_api_key` | 1 |
| cloud-keys | `aws_access_key_id` | 2 |
| cloud-keys | `gcp_api_key` | 1 |
| cloud-keys | `openai_api_key` | 1 |
| network-pii | `email` | 1 |
| network-pii | `image_digest` | 1 |
| network-pii | `ipv4` | 1 |
| network-pii | `ipv6_compressed` | 1 |
| network-pii | `ipv6_full` | 1 |
| network-pii | `mac_address` | 1 |
| network-pii | `url` | 1 |
| network-pii | `user_home_path` | 1 |
| network-pii | `uuid` | 1 |
| saas-tokens | `sendgrid_api_key` | 1 |
| saas-tokens | `slack_token` | 1 |
| saas-tokens | `stripe_key` | 1 |
| saas-tokens | `twilio_account_sid` | 1 |
| secrets-kv | `credential_url` | 1 |
| secrets-kv | `jwt` | 1 |
| secrets-kv | `password_kv` | 2 |
| secrets-kv | `private_key_header` | 1 |
| secrets-kv | `secret_kv` | 2 |
| vcs-ci-tokens | `github_pat_fine_grained` | 1 |
| vcs-ci-tokens | `github_token` | 1 |
| vcs-ci-tokens | `gitlab_token` | 1 |
| vcs-ci-tokens | `huggingface_token` | 1 |
| vcs-ci-tokens | `npm_token` | 1 |

**Totals:** 30 positives across 6 corpus files, 9 hard negatives.
