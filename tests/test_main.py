"""Tests for jesur.main helpers and configuration validation."""
import ipaddress
import pytest

from jesur.main import (
    validate_config,
    _parse_network_token,
    _estimate_host_count,
    _parse_exclude_network_line,
)


def test_validate_config_accepts_minimal():
    validate_config({})


def test_validate_config_rejects_bad_output_dir_type():
    with pytest.raises(ValueError, match="output_dir"):
        validate_config({"output_dir": 123})


def test_parse_network_token_ipv4():
    net = _parse_network_token("192.168.0.0/24")
    assert net == ipaddress.ip_network("192.168.0.0/24")
    assert _estimate_host_count(net) == 254


def test_parse_network_token_ipv6_requires_reasonable_prefix():
    with pytest.raises(ValueError, match="too broad"):
        _parse_network_token("2001:db8::/64")


def test_parse_network_token_ipv6_allowed():
    net = _parse_network_token("2001:db8::/120")
    assert isinstance(net, ipaddress.IPv6Network)
    assert _estimate_host_count(net) == 256


def test_exclude_line_allows_broad_ipv6():
    net = _parse_exclude_network_line("fe80::/10")
    assert isinstance(net, ipaddress.IPv6Network)
    assert net.prefixlen == 10
