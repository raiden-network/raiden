## Description

Please, describe the feature this PR is introducing.

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
- [ ] Test for the new code
    - [ ] Properly covers the new code
    - [ ] If an integration test is used, it could not be written as a unit test
- [ ] Commits
    - [ ] Have good messages
    - [ ] Squashed unecessary commits
- [ ] A changelog entry was added
