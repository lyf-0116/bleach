import pytest

from bleach import clean
from bleach.sanitizer import (
    is_local_fragment_reference,
    remove_nonlocal_css_urls,
)


SVG_TAGS = {"svg", "rect", "pattern"}
SVG_ATTRIBUTES = {
    "rect": ["fill", "stroke"],
    "pattern": ["href", "xlink:href"],
}


@pytest.mark.parametrize(
    "value",
    [
        "url(http://example.com/paint)",
        "URL(http://example.com/paint)",
        "Url(http://example.com/paint)",
        "uRl(http://example.com/paint)",
        "url(  http://example.com/paint  )",
        "URL (http://example.com/paint)",
        "URL('http://example.com/paint')",
        'URL("http://example.com/paint")',
        "URL(&quot;http://example.com/paint&quot;)",
        "&#85;RL(http://example.com/paint)",
        "&#x55;RL(http://example.com/paint)",
        r"\55 RL(http://example.com/paint)",
        r"\000055RL(http://example.com/paint)",
        r"ur\6c(http://example.com/paint)",
        r"url(\68 ttp://example.com/paint)",
        "url(&#104;ttp://example.com/paint)",
        r"url(h\:ttp:\/\/example.com/paint)",
    ],
)
def test_svg_url_references_reject_nonlocal_values(value):
    assert remove_nonlocal_css_urls(value) == ""

    html = f'<svg><rect fill="{value}"></rect></svg>'
    output = clean(html, tags=SVG_TAGS, attributes=SVG_ATTRIBUTES)

    assert "example.com" not in output


@pytest.mark.parametrize(
    "value",
    [
        "url(#paint)",
        "URL(#PAINT)",
        "url(  '#paint'  )",
        'url("#paint")',
        "url(&#35;paint)",
        r"url(\23 paint)",
    ],
)
def test_svg_url_references_keep_local_fragments(value):
    output = remove_nonlocal_css_urls(value)

    assert is_local_fragment_reference(_extract_url(output), css=True)


def _extract_url(css_value):
    start = css_value.index("(") + 1
    end = css_value.rindex(")")
    return css_value[start:end].strip(" \"'")


@pytest.mark.parametrize(
    "href",
    [
        "#pattern",
        "&#35;pattern",
        "&#x23;pattern",
        "\t#pattern",
        "&#9;#pattern",
    ],
)
def test_svg_local_href_kept_after_normalization(href):
    html = f'<svg><pattern href="{href}"></pattern></svg>'
    output = clean(html, tags=SVG_TAGS, attributes=SVG_ATTRIBUTES)

    assert "<pattern" in output
    assert "href=" in output


@pytest.mark.parametrize(
    "href",
    [
        "https://example.com/pattern",
        "&#104;ttps://example.com/pattern",
        "/pattern",
        "pattern",
    ],
)
def test_svg_nonlocal_href_dropped(href):
    html = f'<svg><pattern href="{href}"></pattern></svg>'
    output = clean(html, tags=SVG_TAGS, attributes=SVG_ATTRIBUTES)

    assert "href=" not in output
    assert "example.com" not in output


def test_svg_mixed_local_and_nonlocal_urls():
    value = "url(#keep) URL(http://example.com/remove)"

    assert remove_nonlocal_css_urls(value) == "url(#keep)"

    html = f'<svg><rect fill="{value}"></rect></svg>'
    output = clean(html, tags=SVG_TAGS, attributes=SVG_ATTRIBUTES)

    assert 'fill="url(#keep)"' in output
    assert "example.com" not in output


def test_css_svg_paint_properties_use_same_reference_check():
    pytest.importorskip("tinycss2")
    from bleach.css_sanitizer import CSSSanitizer

    html = '<p style="fill: URL(http://example.com/paint); color: red;">x</p>'
    output = clean(
        html,
        tags={"p"},
        attributes={"p": ["style"]},
        css_sanitizer=CSSSanitizer(),
    )

    assert "example.com" not in output
    assert "color: red" in output

    spaced = '<p style="fill: URL (&quot;http://example.com/paint&quot;);">x</p>'
    spaced_output = clean(
        spaced,
        tags={"p"},
        attributes={"p": ["style"]},
        css_sanitizer=CSSSanitizer(),
    )
    assert "example.com" not in spaced_output


def test_css_relative_url_policy_is_unchanged():
    pytest.importorskip("tinycss2")
    from bleach.css_sanitizer import CSSSanitizer

    html = '<p style="background: url(topbanner.png) #00D;">x</p>'
    output = clean(
        html,
        tags={"p"},
        attributes={"p": ["style"]},
        css_sanitizer=CSSSanitizer(allowed_css_properties=["background"]),
    )

    assert "url(topbanner.png)" in output
