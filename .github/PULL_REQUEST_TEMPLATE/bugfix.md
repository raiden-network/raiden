Fixes: #<issue>

## Description

Please, detail the root cause of the bug and how this PR fixes it.

## PR review check list

Quality check list that cannot be automatically verified.

- [ ] Safety
    - [ ] The changes respect the necessary conditions for safety
- [ ] Code quality
    - [ ] Error conditions are handled
    - [ ] Exceptions are propagated to the correct parent greenlet
    - [ ] Exceptions are correctly classified as recoverable or unrecoverable
- [ ] Compatibility
    - [ ] State changes are forward compatible
    - [ ] Messages are backwards and forward compatible
- [ ] Regression test for the bug
    - [ ] Properly covers the bug
    - [ ] If an integration test is used, it could not be written as a unit test
- [ ] Commits
    - [ ] Have good messages
    - [ ] Squashed unecessary commits
