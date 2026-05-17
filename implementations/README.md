# Implementations

Put each coding-LLM implementation in its own subdirectory here.

Examples:

- `baseline-rust/`
- `gpt-5-4/`
- `claude-sonnet-4-6/`
- `gemini/`
- `qwen/`

## Isolation policy

Each implementation may read:

- `../spec/`
- `../fixtures/`
- `../harness/`

Each implementation should not read sibling implementation directories during generation or repair if you want a fair comparison.
