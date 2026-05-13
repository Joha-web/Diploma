from modules.takeover_checker import TakeoverCheckerModule


def test_takeover_checker_matches_known_cname(tmp_path):
    module = TakeoverCheckerModule("example.com", str(tmp_path), {}, recon_results={})

    finding = module._match_cname("docs.example.com", ["docs.github.io"])

    assert finding is not None
    assert finding["provider"] == "github_pages"
    assert finding["severity"] == "HIGH"
