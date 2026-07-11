"""SPA JS-bundle path mining — pure, no network. Locks the precision/recall of the API-path regex
that makes a form-less SPA's backend (e.g. Juice Shop's /rest/*) visible to the probes."""
from hacklet_runner.jsmine import mine_paths


def test_mines_api_rest_graphql_versioned_paths():
    js = 'this.http.get("/rest/products");a(`/api/Users`);b("/graphql");c("/v1/orders/history")'
    paths = mine_paths(js)
    assert {"/rest/products", "/api/Users", "/graphql", "/v1/orders/history"} <= set(paths)


def test_ignores_client_routes_and_static_assets():
    js = 'a("/login");b("/#/search");c("/assets/x.css");d("/api/main.js");e("/rest/logo.svg")'
    paths = mine_paths(js)
    assert "/login" not in paths          # a client-router path, not a backend API root
    assert "/#/search" not in paths
    assert "/api/main.js" not in paths     # static asset that happens to sit under /api
    assert "/rest/logo.svg" not in paths
    assert all(p.startswith(("/rest", "/api", "/graphql", "/v")) for p in paths)


def test_dedups_and_strips_trailing_slash():
    assert mine_paths('a("/rest/products/");b("/rest/products");c(`/rest/products/`)') == ["/rest/products"]


def test_mines_paths_embedded_in_template_literals():
    # the dominant SPA shape: the API path is a SUFFIX of an interpolated string, not quote-anchored
    js = 'this.http.get(`${restServer}/rest/products/search?q=${term}`);x("h"+"/api/Users")'
    paths = mine_paths(js)
    assert "/rest/products/search" in paths and "/api/Users" in paths


def test_root_boundary_and_bare_root():
    assert mine_paths('a("/apixyz/foo")') == []          # /api glued to a longer word -> not an API path
    assert mine_paths('b(`/graphql`)') == ["/graphql"]   # a bare API root still mines
