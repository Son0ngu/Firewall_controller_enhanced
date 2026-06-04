import os
import sys


AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from shared.server_urls import collect_server_urls, normalize_server_url


def test_normalize_server_url_removes_ui_path_query_and_fragment():
    assert (
        normalize_server_url(
            "https://firewall-controller.onrender.com/api-keys?tab=agent#new"
        )
        == "https://firewall-controller.onrender.com"
    )


def test_normalize_server_url_preserves_localhost_port():
    assert (
        normalize_server_url("http://localhost:5000/api-keys?")
        == "http://localhost:5000"
    )


def test_normalize_server_url_preserves_deployment_subpath():
    assert (
        normalize_server_url("https://school.example.edu/saint")
        == "https://school.example.edu/saint"
    )


def test_normalize_server_url_strips_known_ui_route_after_subpath():
    assert (
        normalize_server_url("https://school.example.edu/saint/api-keys?")
        == "https://school.example.edu/saint"
    )


def test_normalize_server_url_preserves_unknown_path():
    assert (
        normalize_server_url("https://school.example.edu/custom-controller")
        == "https://school.example.edu/custom-controller"
    )


def test_collect_server_urls_normalizes_and_deduplicates():
    urls = collect_server_urls(
        {
            "server": {
                "url": "https://firewall-controller.onrender.com/api-keys?",
                "urls": ["https://firewall-controller.onrender.com/"],
            }
        }
    )

    assert urls == ["https://firewall-controller.onrender.com"]
