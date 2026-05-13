from modules.openapi_parser import OpenAPIParserModule


def test_openapi_parser_extracts_paths_and_parameters(tmp_path):
    module = OpenAPIParserModule("example.com", str(tmp_path), {}, live_hosts=[])
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/users": {
                "get": {
                    "summary": "List users",
                    "parameters": [{"name": "page", "in": "query"}],
                }
            }
        },
    }

    endpoints, params = module._extract(spec, "https://example.com")

    assert endpoints[0]["url"] == "https://example.com/api/users"
    assert endpoints[0]["method"] == "GET"
    assert params[0]["name"] == "page"
