# Supported Categories

Replacements are **length-preserving** — every replacement has the exact same byte count as the original match. Formatting characters (dots, dashes, colons, `@`) are preserved in place while variable portions are filled with deterministic hex digits or table-indexed names. This ensures replacements can be dropped into size-sensitive contexts (fixed-width columns, binary offsets, structured logs) without breaking alignment.

| Category | Replacement Strategy | Example (original → replacement) |
|----------|---------------------|-----------------------------------|
| `email` | Preserve domain; fill username with hex to match length | `alice@corp.com` → `a1b2c@corp.com` |
| `name` | Select synthetic name from hash-indexed table; truncate or pad to match length | `John Doe` → `Alex Ash` |
| `phone` | Preserve formatting characters (`+`, `-`, spaces); replace digits with deterministic digits | `+1-212-555-0100` → `+3-974-182-6305` |
| `ipv4` | Preserve dots; replace each digit with a deterministic digit (may produce octets > 255) | `192.168.1.1` → `837.042.9.3` |
| `ipv6` | Preserve colons and `::` structure; replace hex digits | `fd00:abcd::1` → `e2a7:93f1::8` |
| `mac_address` | Preserve `:` or `-` separators; replace hex digits | `AA:BB:CC:DD:EE:FF` → `3f:a7:92:c1:8e:d4` |
| `hostname` | Preserve domain suffix (from first `.`); fill prefix with hex to match length | `db-prod-01.internal` → `a1b2c3d4e5.internal` |
| `container_id` | Replace hex digits deterministically | `a1b2c3d4e5f6` → `3fa792c18ed4` |
| `uuid` | Preserve `-` dashes; replace hex digits | `550e8400-e29b-41d4-a716-446655440000` → `3fa79c12-8ed4-b1a7-290c-e18d43fa7b92` |
| `jwt` | Preserve `.` separators; replace base64url characters | `eyJhbG.eyJzdW.SflKxw` → `Rk3pA7.x9Qm2B.Hn4dYc` |
| `auth_token` | `__SANITIZED_<hex>__` wrapper (same as custom) | `ghp_abc123secrettoken` → `__SANITIZED_3fa7__` (21 chars) |
| `credit_card` | Preserve dashes/spaces; replace digits with deterministic digits | `4111-1111-1111-1111` → `8370-4293-6152-8074` |
| `ssn` | Preserve dashes; force first 3 digits to `000` (clearly synthetic); fill rest with deterministic digits | `123-45-6789` → `000-83-7042` |
| `file_path` | Preserve `/`, `\`, and file extension; replace segment content with hex | `/home/jsmith/config.yaml` → `/3fa7/92c18e/d43fa7.yaml` |
| `windows_sid` | Preserve `S-` prefix and `-` separators; replace digit groups | `S-1-5-21-3623811015` → `S-3-7-92-1843fa792c` |
| `url` | Preserve scheme and structural characters (`://`, `/`, `?`, `=`, `&`, `#`); replace content | `https://internal.corp.com/api` → `https://3fa792c18ed4.3fa.792/c18` |
| `aws_arn` | Preserve `:` and `/` separators; replace content segments with hex | `arn:aws:iam::123456789012:user/admin` → `arn:3fa:792::c18ed43fa792:3fa7/92c18` |
| `azure_resource_id` | Preserve `/` separators and well-known segment names (`subscriptions`, `resourceGroups`, `providers`); replace variable segments | `/subscriptions/550e8400/resourceGroups/rg-prod` → `/subscriptions/3fa792c1/resourceGroups/8ed43fa7` |
| `custom:<tag>` | `__SANITIZED_<hex>__` wrapper, padded/truncated to match length; short inputs use bare hex | `sk-proj-abc123secret` → `__SANITIZED_a1b2__` (20 chars) |

## Adding Custom Categories

Any category string that does not match a built-in name is treated as a custom category. Use the `custom:<tag>` prefix convention:

```json
{
  "pattern": "internal_project_code_[A-Z0-9]+",
  "kind": "regex",
  "category": "custom:project_code",
  "label": "project_code"
}
```

Custom categories produce replacements in the format `__SANITIZED_<hex>__`, where the hex portion is sized so the total replacement length matches the original. The category tag (`project_code` in this example) participates in HMAC domain separation, so the same plaintext value under different custom tags produces different replacements. For originals shorter than 14 characters (the `__SANITIZED_` + `__` overhead), bare hex is used instead.

Category strings without the `custom:` prefix that do not match a built-in name (`email`, `name`, `phone`, `ipv4`, `ipv6`, `credit_card`, `ssn`, `hostname`, `mac_address`, `container_id`, `uuid`, `jwt`, `auth_token`, `file_path`, `windows_sid`, `url`, `aws_arn`, `azure_resource_id`) are also routed to the custom formatter.
