## Description

Fixes: #<issue>

Please, describe what this PR does in detail:
- If it's a bug fix, detail the root cause of the bug and how this PR fixes it.
- If it's a new feature, describe the feature this PR is introducing and design decisions.
- If it's a refactoring, describe why it is necessary. What are its pros and cons in respect to the previous code, and other possible design choices.

## PR review check list

Quality check list that cannot be automatically verified.

- Safety
    - [ ] The changes respect the necessary conditions for safety (https://raiden-network-specification.readthedocs.io/en/latest/smart_contracts.html#protocol-values-constraints)
-  Code quality
    - [ ] Error conditions are handled
    - [ ] Exceptions are propagated to the correct parent greenlet
    - [ ] Exceptions are correctly classified as recoverable or unrecoverable
- Compatibility
    - [ ] State changes are forward compatible
    - [ ] Transport messages are backwards and forward compatible
- Commits
    - [ ] Have good messages
    - [ ] Squashed unecessary commits
- If it's a bug fix:
    - Regression test for the bug
        - [ ] Properly covers the bug
        - [ ] If an integration test is used, it could not be written as a unit test
- Documentation
    - [ ] A new CLI flag was introduced, is there documentation that explains usage?
- Specs
    - [ ] If this is a protocol change, are the specs updated accordingly? If so, please link PR from the specs repo.
- Is it a user facing feature/bug fix?
    - [ ] Changelog entry has been added
