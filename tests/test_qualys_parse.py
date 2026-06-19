"""Unit tests for the low-level ElementTree helpers in ``sources.qualys.parse``."""

from __future__ import annotations

from xml.etree.ElementTree import fromstring

from qjsync.sources.qualys import parse

_SAMPLE = """
<ROOT>
  <STR>  hello  </STR>
  <EMPTY>   </EMPTY>
  <INT>42</INT>
  <INT_DECIMAL>5.0</INT_DECIMAL>
  <FLOAT>9.3</FLOAT>
  <BOOL_TRUE>1</BOOL_TRUE>
  <BOOL_FALSE>0</BOOL_FALSE>
  <BOOL_OTHER>maybe</BOOL_OTHER>
  <BAD_INT>abc</BAD_INT>
  <LIST>
    <ITEM><NAME>a</NAME></ITEM>
    <ITEM><NAME>b</NAME></ITEM>
    <ITEM><NAME>   </NAME></ITEM>
    <ITEM><NAME>c</NAME></ITEM>
  </LIST>
</ROOT>
"""


def _root() -> object:
    return fromstring(_SAMPLE)


def test_text_strips_and_handles_absence() -> None:
    root = _root()
    assert parse.text(root, "STR") == "hello"
    assert parse.text(root, "EMPTY") is None
    assert parse.text(root, "MISSING") is None
    assert parse.text(None, "STR") is None


def test_text_self_path() -> None:
    el = fromstring("<NAME> x </NAME>")
    assert parse.text(el, ".") == "x"


def test_intval() -> None:
    root = _root()
    assert parse.intval(root, "INT") == 42
    assert parse.intval(root, "INT_DECIMAL") == 5  # tolerate "5.0"
    assert parse.intval(root, "BAD_INT") is None
    assert parse.intval(root, "MISSING") is None


def test_floatval() -> None:
    root = _root()
    assert parse.floatval(root, "FLOAT") == 9.3
    assert parse.floatval(root, "BAD_INT") is None
    assert parse.floatval(root, "MISSING") is None


def test_boolval() -> None:
    root = _root()
    assert parse.boolval(root, "BOOL_TRUE") is True
    assert parse.boolval(root, "BOOL_FALSE") is False
    assert parse.boolval(root, "BOOL_OTHER") is None  # unknown != False
    assert parse.boolval(root, "MISSING") is None


def test_texts_list_extractor_skips_blank() -> None:
    root = _root()
    assert parse.texts(root, "LIST/ITEM/NAME") == ["a", "b", "c"]
    assert parse.texts(None, "LIST/ITEM/NAME") == []
    assert parse.texts(root, "MISSING/NAME") == []


def test_find_all_and_iter_elements() -> None:
    root = _root()
    assert len(parse.find_all(root, "LIST/ITEM")) == 4
    assert len(list(parse.iter_elements(root, "LIST/ITEM"))) == 4
    assert parse.find_all(None, "LIST/ITEM") == []
