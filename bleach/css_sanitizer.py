import tinycss2

from bleach.html5lib_shim import svg_attr_val_allows_ref
from bleach.sanitizer import is_external_reference


ALLOWED_CSS_PROPERTIES = frozenset(
    (
        "azimuth",
        "background-color",
        "border-bottom-color",
        "border-collapse",
        "border-color",
        "border-left-color",
        "border-right-color",
        "border-top-color",
        "clear",
        "color",
        "cursor",
        "direction",
        "display",
        "elevation",
        "float",
        "font",
        "font-family",
        "font-size",
        "font-style",
        "font-variant",
        "font-weight",
        "height",
        "letter-spacing",
        "line-height",
        "overflow",
        "pause",
        "pause-after",
        "pause-before",
        "pitch",
        "pitch-range",
        "richness",
        "speak",
        "speak-header",
        "speak-numeral",
        "speak-punctuation",
        "speech-rate",
        "stress",
        "text-align",
        "text-decoration",
        "text-indent",
        "unicode-bidi",
        "vertical-align",
        "voice-family",
        "volume",
        "white-space",
        "width",
    )
)


ALLOWED_SVG_PROPERTIES = frozenset(
    (
        "fill",
        "fill-opacity",
        "fill-rule",
        "stroke",
        "stroke-width",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-opacity",
    )
)


SVG_LOCAL_URL_PROPERTIES = frozenset(
    name for namespace, name in svg_attr_val_allows_ref if namespace is None
)


class CSSSanitizer:
    def __init__(
        self,
        allowed_css_properties=ALLOWED_CSS_PROPERTIES,
        allowed_svg_properties=ALLOWED_SVG_PROPERTIES,
    ):
        self.allowed_css_properties = allowed_css_properties
        self.allowed_svg_properties = allowed_svg_properties

    def sanitize_css(self, style):
        """Sanitizes css in style tags"""
        parsed = tinycss2.parse_declaration_list(style)

        if not parsed:
            return ""

        new_tokens = []
        for token in parsed:
            if token.type == "declaration":
                if (
                    token.lower_name in self.allowed_css_properties
                    or token.lower_name in self.allowed_svg_properties
                ):
                    if (
                        token.lower_name in SVG_LOCAL_URL_PROPERTIES
                        and token.lower_name in self.allowed_svg_properties
                    ):
                        token.value = _sanitize_local_url_tokens(token.value)
                    new_tokens.append(token)
            elif token.type in ("comment", "whitespace"):
                if new_tokens and new_tokens[-1].type != token.type:
                    new_tokens.append(token)

            # NOTE(willkg): We currently don't handle AtRule or ParseError and
            # so both get silently thrown out

        if not new_tokens:
            return ""

        return tinycss2.serialize(new_tokens).strip()


def _sanitize_local_url_tokens(tokens):
    """Drops non-fragment URL tokens from SVG paint properties."""
    sanitized = []
    index = 0
    while index < len(tokens):
        token = tokens[index]

        if token.type == "url":
            if not is_external_reference(token.value):
                sanitized.append(token)
            index += 1
            continue

        if token.type in ("function", "function-block") and (token.lower_name == "url"):
            raw_url = _string_function_url(token)
            if raw_url is not None and not is_external_reference(raw_url):
                sanitized.append(token)
            index += 1
            continue

        if token.type == "ident" and token.lower_value == "url":
            block_index = index + 1
            while (
                block_index < len(tokens) and tokens[block_index].type == "whitespace"
            ):
                block_index += 1

            if block_index < len(tokens) and tokens[block_index].type == "() block":
                raw_url = _parentheses_block_url(tokens[block_index])
                if raw_url is not None and not is_external_reference(raw_url):
                    sanitized.extend(tokens[index : block_index + 1])
                index = block_index + 1
                continue

        sanitized.append(token)
        index += 1

    return sanitized


def _string_function_url(token):
    string_tokens = [arg for arg in token.arguments if arg.type == "string"]
    if len(string_tokens) == 1:
        return string_tokens[0].value
    return None


def _parentheses_block_url(token):
    string_tokens = [arg for arg in token.content if arg.type == "string"]
    if len(string_tokens) == 1:
        return string_tokens[0].value
    if string_tokens:
        return None
    return tinycss2.serialize(token.content).strip()
