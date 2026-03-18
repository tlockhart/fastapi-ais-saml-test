import pytest

from utils.dict_utils import _deep_merge


def test_deep_merge_adds_new_keys():
    target = {"a": 1}
    overrides = {"b": 2}
    _deep_merge(target, overrides)
    assert target == {"a": 1, "b": 2}


def test_deep_merge_overwrites_primitives():
    target = {"a": 1, "b": 2}
    overrides = {"b": 20}
    _deep_merge(target, overrides)
    assert target == {"a": 1, "b": 20}


def test_deep_merge_merges_nested_dicts():
    target = {"a": {"x": 1, "y": 2}, "c": 3}
    overrides = {"a": {"y": 20, "z": 30}, "d": 4}
    _deep_merge(target, overrides)
    assert target == {"a": {"x": 1, "y": 20, "z": 30}, "c": 3, "d": 4}
