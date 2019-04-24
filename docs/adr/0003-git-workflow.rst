Raiden Team - Git Workflow
==========================

* **Status**: proposed
* **Deciders**: @lefterisjp, @hackaugusto, @konradkonrad, @rakanalh
* **Date**: 2019-04-15


Context and Problem Statement
-----------------------------

The current workflow team members in the Raiden team currently use is as simple as pick issues, create a respective branch for that issue and present a PR once the bug/feature is fixed/implemented.

This newly created branch will be merged into master regardless of what category the implementation falls into. There are currently 3 categories that a single PR can have:
1. Bug fix
2. Feature
3. Enhancement / Refactorings

Right now, all of these branches which can have any combination of those 3 categories will be merged into the master branch once it undergoes code review. However, we have come to realize that merging everything into master will cause our code to have a mixture of:
1. The bug fixes that we should release to the public.
2. Features that move Raiden forward into integrating with the PFS / MS services (which are under heavy development)
3. Code refactorings that address certain technical debts the team is constantly finding issues in, and/or is annoying and hard to work with.

The set of problems that the team finds in this approach is:
1. It is getting harder to make faster release cycles provided that some new code paths might be executed which are intended to support a new feature that Red-Eyes users should not / are not supposed to use.
2. Large issues are broken into smaller, self-contained PRs which move Raiden forward towards resolving the issue collectively but not individually. The justification for this is to have smaller PRs to review which is a huge advantange. However, this could potentially leave us with a state where the master branch is broken.


Decision Drivers
----------------

* Increase the velocity of progress
* Pave the way for faster mainnet release cycles
* Have certain recent checkpoints in the project's codebase where new features / functionalities are known to be stable.


Considered Options
------------------

Original proposal
~~~~~~~~~~~~~~~~~

After discussing this with @hackaugusto, @LefterisJP and @konradkonrad, we realized that we need to come up with a better way to separate our workflow for bug fixing from the ones for introducing new features and refactoring of the code base.

So, we seem to agree on using parts of the git-workflow where:
1. A `develop` branch is introduced.
2. The `master` branch will be our "production-ready" branch.
3. When a bug is reported, the assignee of the issue will branch of the latest master, provide a fix which will be merged into both `master` and `develop`.
4. The `develop` branch will contain all the work we do for new features and code refactorings.
5. Once any code changes are merged to master, `develop` should be merged on top of the latest master to ensure that our fixes are also residing in the develop branch in case any team member is working on the same code base.

The Pros of this new workflow:
1. Resolving bugs, merging them to master and instantly creating a release which contains the new bug fix(es)
2. Removing the worry about a broken `master` branch because the `develop` branch is going to contain all the potential breaking changes whose issues will be resolved separately.
3. Enable separate test configurations where the `master` would run tests on CI with `production` settings while `develop` runs with `development` configurations.

The Cons of this approach:
1. Rebasing `develop` should some how be automated as soon as any changes are merged into master, or otherwise if both branches diverge alot from each other, this could be a pain to resolve all the conflicts and get the develop branch back in shape.
2. It's a new workflow so team members have to get used to this and map what they're working on to the destination branch on which their implementation will land.

"Successful branching model"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It was suggested to follow `The Successful git branching model`_ which is quite similar to the original proposal.

.. _The successful Git branching model: https://nvie.com/posts/a-successful-git-branching-model/

Decision Outcome
----------------

It was decided to follow the "Successful git branching model" option which is conveyed by the following:

.. image:: https://user-images.githubusercontent.com/44281/56030116-5cdd8680-5d1c-11e9-8de8-d3fb61ad7d8e.png

Where:

- `master` is maintained to be production-ready branch.
- `develop` is the target branch for new features.
- New feature branches are merged into develop.
- Bug fixes are merged into both `develop` and `master`.
- Nightly builds are created on latest `develop`.
- If a certain nightly is to be released, a release branch is created to include changes required for creating that release such as bumpversion.
  Bug fixes specific to a certain release would be merged into that release branch.
- Once a mainnet release is out, develop is merged into master and the process is restarted.
- Provided we follow the sematic versioning scheme, every bug fix should be rolled out with a new **minor** version.
