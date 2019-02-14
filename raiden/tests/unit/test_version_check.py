import json
import re
from unittest.mock import patch

import requests
from pkg_resources import parse_version

from raiden.tasks import SECURITY_EXPRESSION, _do_check_version

LATEST_RELEASE_RESPONSE = """{"url":
            "https://api.github.com/repos/raiden-network/raiden/releases/14541434",
            "assets_url":
            "https://api.github.com/repos/raiden-network/raiden/releases/14541434/assets",
            "upload_url":
            "https://uploads.github.com/repos/raiden-network/raiden/releases/14541434/assets{?name,label}",
            "html_url":
            "https://github.com/raiden-network/raiden/releases/tag/v0.19.0",
            "id": 14541434, "node_id": "MDc6UmVsZWFzZTE0NTQxNDM0",
            "tag_name": "v0.19.0", "target_commitish":
            "53b8eee062e3e309486ea438c9487f349b964c11", "name":
            "v0.19.0 - Polaroid", "draft": false, "author": {"login":
            "LefterisJP", "id": 1658405, "node_id":
            "MDQ6VXNlcjE2NTg0MDU=", "avatar_url":
            "https://avatars1.githubusercontent.com/u/1658405?v=4",
            "gravatar_id": "", "url":
            "https://api.github.com/users/LefterisJP", "html_url":
            "https://github.com/LefterisJP", "followers_url":
            "https://api.github.com/users/LefterisJP/followers",
            "following_url":
            "https://api.github.com/users/LefterisJP/following{/other_user}",
            "gists_url":
            "https://api.github.com/users/LefterisJP/gists{/gist_id}",
            "starred_url":
            "https://api.github.com/users/LefterisJP/starred{/owner}{/repo}",
            "subscriptions_url":
            "https://api.github.com/users/LefterisJP/subscriptions",
            "organizations_url":
            "https://api.github.com/users/LefterisJP/orgs",
            "repos_url":
            "https://api.github.com/users/LefterisJP/repos",
            "events_url":
            "https://api.github.com/users/LefterisJP/events{/privacy}",
            "received_events_url":
            "https://api.github.com/users/LefterisJP/received_events",
            "type": "User", "site_admin": false}, "prerelease": false,
            "created_at": "2018-12-14T16:49:07Z", "published_at":
            "2018-12-14T16:50:36Z", "assets": [{"url":
            "https://api.github.com/repos/raiden-network/raiden/releases/assets/10155617",
            "id": 10155617, "node_id":
            "MDEyOlJlbGVhc2VBc3NldDEwMTU1NjE3", "name":
            "raiden-v0.19.0-linux.tar.gz", "label": "", "uploader":
            {"login": "konradkonrad", "id": 3705643, "node_id":
            "MDQ6VXNlcjM3MDU2NDM=", "avatar_url":
            "https://avatars3.githubusercontent.com/u/3705643?v=4",
            "gravatar_id": "", "url":
            "https://api.github.com/users/konradkonrad", "html_url":
            "https://github.com/konradkonrad", "followers_url":
            "https://api.github.com/users/konradkonrad/followers",
            "following_url":
            "https://api.github.com/users/konradkonrad/following{/other_user}",
            "gists_url":
            "https://api.github.com/users/konradkonrad/gists{/gist_id}",
            "starred_url":
            "https://api.github.com/users/konradkonrad/starred{/owner}{/repo}",
            "subscriptions_url":
            "https://api.github.com/users/konradkonrad/subscriptions",
            "organizations_url":
            "https://api.github.com/users/konradkonrad/orgs",
            "repos_url":
            "https://api.github.com/users/konradkonrad/repos",
            "events_url":
            "https://api.github.com/users/konradkonrad/events{/privacy}",
            "received_events_url":
            "https://api.github.com/users/konradkonrad/received_events",
            "type": "User", "site_admin": false}, "content_type":
            "application/gzip", "state": "uploaded", "size": 19201827,
            "download_count": 22, "created_at":
            "2018-12-14T17:03:57Z", "updated_at":
            "2018-12-14T17:03:58Z", "browser_download_url":
            "https://github.com/raiden-network/raiden/releases/download/v0.19.0/raiden-v0.19.0-linux.tar.gz"},
            {"url":
            "https://api.github.com/repos/raiden-network/raiden/releases/assets/10155709",
            "id": 10155709, "node_id":
            "MDEyOlJlbGVhc2VBc3NldDEwMTU1NzA5", "name":
            "raiden-v0.19.0-macOS.zip", "label": "", "uploader":
            {"login": "konradkonrad", "id": 3705643, "node_id":
            "MDQ6VXNlcjM3MDU2NDM=", "avatar_url":
            "https://avatars3.githubusercontent.com/u/3705643?v=4",
            "gravatar_id": "", "url":
            "https://api.github.com/users/konradkonrad", "html_url":
            "https://github.com/konradkonrad", "followers_url":
            "https://api.github.com/users/konradkonrad/followers",
            "following_url":
            "https://api.github.com/users/konradkonrad/following{/other_user}",
            "gists_url":
            "https://api.github.com/users/konradkonrad/gists{/gist_id}",
            "starred_url":
            "https://api.github.com/users/konradkonrad/starred{/owner}{/repo}",
            "subscriptions_url":
            "https://api.github.com/users/konradkonrad/subscriptions",
            "organizations_url":
            "https://api.github.com/users/konradkonrad/orgs",
            "repos_url":
            "https://api.github.com/users/konradkonrad/repos",
            "events_url":
            "https://api.github.com/users/konradkonrad/events{/privacy}",
            "received_events_url":
            "https://api.github.com/users/konradkonrad/received_events",
            "type": "User", "site_admin": false}, "content_type":
            "application/zip", "state": "uploaded", "size": 20103162,
            "download_count": 5, "created_at": "2018-12-14T17:11:51Z",
            "updated_at": "2018-12-14T17:11:52Z",
            "browser_download_url":
            "https://github.com/raiden-network/raiden/releases/download/v0.19.0/raiden-v0.19.0-macOS.zip"}],
            "tarball_url":
            "https://api.github.com/repos/raiden-network/raiden/tarball/v0.19.0",
            "zipball_url":
            "https://api.github.com/repos/raiden-network/raiden/zipball/v0.19.0",
            "body": "# DescriptionThis is the latest weekly
            testnet release in preparation for the Red Eyes mainnet
            release.Numerous bugs were fixed this week including
            some submitted by the users of Raiden in the Singapore
            hackathon.**This is a compatibility breaking
            release which alters the database format. A new database
            will be automatically created for you. Also note that the
            Rest API versioning format has changed. A `v` prefix is
            added to the API version.** If you are upgrading
            from an earlier version you will first need to **close and
            settle** all your channels with the previous version
            before using this new version.#
            Miscellaneous- #3157 Change REST api version
            prefix from 1 to v1.# Bug Fixes- #3153 If
            a non-contract address is given for token_address in the
            channel open REST API call, the client no longer
            crashes.- #3152 If the onchain unlock has already been
            mined when we try to send the transaction Raiden no longer
            crashes.- #3135 In development mode if more than 100 *
            (10^18) tokens are deposited then Raiden no longer
            crashes."}"""


def test_version_check_regex():
    text1 = "Something OTHER UPDATE. [CRITICAL UPDATE Some text.:)]. Something else."
    text2 = "\n\n[CRITICAL\t UPDATE] some text goes here."
    text3 = "[NOTHING]"
    text4 = "asd[CRITICAL UPDATE]"
    text5 = "Other text [CRITICAL UPDATE:>>>>>>>]><<<<asdeqsffqwe qwe sss."
    text6 = "\n\n[CRITICAL UPDATE: U+1F00 1F62D ❎ 😀] some text goes here."
    assert re.search(SECURITY_EXPRESSION, text1).group(0) == '[CRITICAL UPDATE Some text.:)]'
    assert re.search(SECURITY_EXPRESSION, text2) is None
    assert re.search(SECURITY_EXPRESSION, text3) is None
    assert re.search(SECURITY_EXPRESSION, text4).group(0) == '[CRITICAL UPDATE]'
    assert re.search(SECURITY_EXPRESSION, text5).group(0) == '[CRITICAL UPDATE:>>>>>>>]'
    assert re.search(SECURITY_EXPRESSION, text6).group(0) == '[CRITICAL UPDATE: U+1F00 1F62D ❎ 😀]'
    assert re.search(SECURITY_EXPRESSION, text6).group(0) != '[CRITICAL UPDATE: U+1F00 1F62D ❎'


def test_version_check_api_rate_limit_exceeded():
    version = parse_version('0.17.1.dev205+ge7a0c6ad')

    class Response():
        @staticmethod
        def json():
            response = """{"message": "API rate limit exceeded for 62.96.232.178. (But here's the
             good news: Authenticated requests get a higher rate limit. Check out the
            documentation for more details.)", "documentation_url":
            "https://developer.github.com/v3/#rate-limiting"}"""
            return json.loads(response.replace('\n', ''))

    def fake_request(endpoint):
        return Response()

    with patch.object(requests, 'get', side_effect=fake_request):
        assert not _do_check_version(version)


def test_version_check():
    version = parse_version('0.17.1.dev205+ge7a0c6ad')

    class Response():
        @staticmethod
        def json():
            return json.loads(LATEST_RELEASE_RESPONSE.replace('\n', ''))

    def fake_request(endpoint):
        return Response()

    with patch.object(requests, 'get', side_effect=fake_request):
        assert not _do_check_version(version)
        assert _do_check_version(parse_version('0.19.0'))
