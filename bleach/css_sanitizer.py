import tinycss2


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


class CSSSanitizer:
    def __init__(
        self,
        allowed_css_properties=ALLOWED_CSS_PROPERTIES,
        allowed_svg_properties=ALLOWED_SVG_PROPERTIES,
        allowed_protocols=None,
        uri_context="style",
        uri_validator=None,
        **kwargs,
    ):
        self.allowed_css_properties = allowed_css_properties
        self.allowed_svg_properties = allowed_svg_properties
        if allowed_protocols is None:
            allowed_protocols = kwargs.get("protocols")
        self.allowed_protocols = allowed_protocols
        self.uri_context = (
            kwargs.get("context") or kwargs.get("scenario") or uri_context
        )
        self.uri_validator = uri_validator

    def _uri_is_allowed(self, uri, allowed_protocols=None, context=None):
        protocols = allowed_protocols
        if protocols is None:
            protocols = self.allowed_protocols
        if context is None:
            context = self.uri_context

        if self.uri_validator is not None:
            try:
                result = self.uri_validator(uri, protocols, context)
            except TypeError:
                try:
                    result = self.uri_validator(uri, protocols)
                except TypeError:
                    result = self.uri_validator(uri)
            return result is not None and result is not False

        from bleach.sanitizer import ALLOWED_PROTOCOLS, sanitize_uri_value

        if protocols is None:
            protocols = ALLOWED_PROTOCOLS
        return (
            sanitize_uri_value(
                uri,
                protocols,
                context=context,
            )
            is not None
        )

    def _component_values_have_disallowed_url(
        self, tokens, allowed_protocols, context=None
    ):
        stack = list(tokens)
        while stack:
            token = stack.pop()
            token_type = getattr(token, "type", None)

            if token_type == "url":
                if not self._uri_is_allowed(token.value, allowed_protocols, context):
                    return True
                continue

            if token_type == "function" and getattr(token, "lower_name", "") == "url":
                arguments = getattr(token, "arguments", ())
                for argument in arguments:
                    if getattr(argument, "type", None) == "string":
                        if not self._uri_is_allowed(
                            argument.value, allowed_protocols, context
                        ):
                            return True
                stack.extend(arguments)
                continue

            child_tokens = getattr(token, "arguments", None)
            if child_tokens:
                stack.extend(child_tokens)

        return False

    def sanitize_css(self, style, allowed_protocols=None, **kwargs):
        """Sanitizes css in style tags"""
        if allowed_protocols is None:
            allowed_protocols = kwargs.get("protocols")
        uri_context = (
            kwargs.get("context")
            or kwargs.get("uri_context")
            or kwargs.get("scenario")
            or self.uri_context
        )

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
                    if self._component_values_have_disallowed_url(
                        token.value, allowed_protocols, uri_context
                    ):
                        continue
                    new_tokens.append(token)
            elif token.type in ("comment", "whitespace"):
                if new_tokens and new_tokens[-1].type != token.type:
                    new_tokens.append(token)

            # NOTE(willkg): We currently don't handle AtRule or ParseError and
            # so both get silently thrown out

        if not new_tokens:
            return ""

        return tinycss2.serialize(new_tokens).strip()
