from itertools import chain
import inspect
import re
import warnings

from xml.sax.saxutils import unescape

from bleach import html5lib_shim
from bleach import parse_shim


#: Set of allowed tags
ALLOWED_TAGS = frozenset(
    (
        "a",
        "abbr",
        "acronym",
        "b",
        "blockquote",
        "code",
        "em",
        "i",
        "li",
        "ol",
        "strong",
        "ul",
    )
)


#: Map of allowed attributes by tag
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "abbr": ["title"],
    "acronym": ["title"],
}

#: Set of allowed protocols
ALLOWED_PROTOCOLS = frozenset(("http", "https", "mailto"))


# URI usage contexts. Navigation may safely use protocol-relative references
# because the browser only navigates to them. Resource contexts cause the
# response to be loaded or interpreted, so external protocol-relative
# references are treated as a distinct, higher-risk policy.
URI_CONTEXT_NAVIGATION = "navigation"
URI_CONTEXT_RESOURCE = "resource"
URI_CONTEXT_STYLE = "style"
URI_CONTEXT_LEGACY = "legacy"

# Omitted contexts fail closed. Internal HTML call sites always classify the
# attribute explicitly; direct callers that need the old policy can opt into
# URI_CONTEXT_LEGACY.
URI_CONTEXT_DEFAULT = URI_CONTEXT_RESOURCE

# Contexts in which network-path references (``//host/path`` and browser-
# equivalent separator forms) are part of the allowed reference set.
PROTOCOL_RELATIVE_URI_CONTEXTS = frozenset((URI_CONTEXT_NAVIGATION, URI_CONTEXT_LEGACY))

# Descriptive aliases for callers that name contexts by HTML attribute.
URI_CONTEXT_LINK = URI_CONTEXT_NAVIGATION
URI_CONTEXT_HREF = URI_CONTEXT_NAVIGATION
URI_CONTEXT_SRC = URI_CONTEXT_RESOURCE


class UriContext:
    """Named URI usage scenarios accepted by :func:`sanitize_uri_value`."""

    DEFAULT = URI_CONTEXT_DEFAULT
    LEGACY = URI_CONTEXT_LEGACY
    LINK = URI_CONTEXT_NAVIGATION
    NAVIGATION = URI_CONTEXT_NAVIGATION
    HREF = URI_CONTEXT_NAVIGATION
    RESOURCE = URI_CONTEXT_RESOURCE
    SRC = URI_CONTEXT_RESOURCE
    STYLE = URI_CONTEXT_STYLE


URIContext = UriContext
UrlContext = UriContext
URLContext = UriContext


_CONTEXT_ALIASES = {
    None: URI_CONTEXT_RESOURCE,
    "": URI_CONTEXT_RESOURCE,
    "default": URI_CONTEXT_RESOURCE,
    "safe": URI_CONTEXT_RESOURCE,
    "secure": URI_CONTEXT_RESOURCE,
    "generic": URI_CONTEXT_LEGACY,
    "uri": URI_CONTEXT_LEGACY,
    "url": URI_CONTEXT_LEGACY,
    "auto": URI_CONTEXT_LEGACY,
    "legacy": URI_CONTEXT_LEGACY,
    "compatibility": URI_CONTEXT_LEGACY,
    "link": URI_CONTEXT_NAVIGATION,
    "links": URI_CONTEXT_NAVIGATION,
    "anchor": URI_CONTEXT_NAVIGATION,
    "a": URI_CONTEXT_NAVIGATION,
    "navigation": URI_CONTEXT_NAVIGATION,
    "navigate": URI_CONTEXT_NAVIGATION,
    "href": URI_CONTEXT_NAVIGATION,
    "action": URI_CONTEXT_NAVIGATION,
    "form": URI_CONTEXT_NAVIGATION,
    "forms": URI_CONTEXT_NAVIGATION,
    "button": URI_CONTEXT_NAVIGATION,
    "formaction": URI_CONTEXT_NAVIGATION,
    "ping": URI_CONTEXT_NAVIGATION,
    "cite": URI_CONTEXT_NAVIGATION,
    "longdesc": URI_CONTEXT_NAVIGATION,
    "resource": URI_CONTEXT_RESOURCE,
    "resources": URI_CONTEXT_RESOURCE,
    "asset": URI_CONTEXT_RESOURCE,
    "assets": URI_CONTEXT_RESOURCE,
    "embed": URI_CONTEXT_RESOURCE,
    "embedded": URI_CONTEXT_RESOURCE,
    "frame": URI_CONTEXT_RESOURCE,
    "iframe": URI_CONTEXT_RESOURCE,
    "object": URI_CONTEXT_RESOURCE,
    "data": URI_CONTEXT_RESOURCE,
    "script": URI_CONTEXT_RESOURCE,
    "media": URI_CONTEXT_RESOURCE,
    "img": URI_CONTEXT_RESOURCE,
    "image": URI_CONTEXT_RESOURCE,
    "src": URI_CONTEXT_RESOURCE,
    "poster": URI_CONTEXT_RESOURCE,
    "background": URI_CONTEXT_RESOURCE,
    "active": URI_CONTEXT_RESOURCE,
    "loading": URI_CONTEXT_RESOURCE,
    "load": URI_CONTEXT_RESOURCE,
    "dangerous": URI_CONTEXT_RESOURCE,
    "strict": URI_CONTEXT_RESOURCE,
    "style": URI_CONTEXT_STYLE,
    "css": URI_CONTEXT_STYLE,
}


# Attributes whose values are navigated to rather than loaded as a resource.
# ``href`` is resolved per-tag because elements such as ``link`` and SVG
# ``use`` also use href to load resources.
NAVIGATION_URI_ATTRIBUTES = frozenset(
    ("action", "formaction", "ping", "cite", "longdesc")
)

# Tags for which href-like attributes cause a resource to be loaded.
RESOURCE_HREF_TAGS = frozenset(
    ("link", "use", "image", "feimage", "script", "audio", "video", "source")
)

# html5lib's URI set predates some object/data usage; keep the additions
# explicit so callers passing a custom attr_val_is_uri retain that policy.
EXTRA_URI_ATTRIBUTES = frozenset(("data",))

#: Invisible characters--0 to and including 31 except 9 (tab), 10 (lf), and 13 (cr)
INVISIBLE_CHARACTERS = "".join(
    [chr(c) for c in chain(range(0, 9), range(11, 13), range(14, 32))]
)

#: Regexp for characters that are invisible
INVISIBLE_CHARACTERS_RE = re.compile("[" + INVISIBLE_CHARACTERS + "]", re.UNICODE)

#: String to replace invisible characters with. This can be a character, a
#: string, or even a function that takes a Python re matchobj
INVISIBLE_REPLACEMENT_CHAR = "?"


class NoCssSanitizerWarning(UserWarning):
    pass


def _context_value(context):
    """Returns the string value for a context or context-like object."""
    value = getattr(context, "value", context)
    if value is None:
        return None
    return str(value).strip().lower()


def normalize_uri_context(context=None, **aliases):
    """Normalizes a URI context argument to one of the supported constants."""
    if context is None:
        for name, value in aliases.items():
            normalized_name = name.lower()
            if (
                any(
                    term in normalized_name
                    for term in (
                        "context",
                        "scenario",
                        "scene",
                        "usage",
                        "purpose",
                        "location",
                        "position",
                        "placement",
                    )
                )
                and value is not None
            ):
                context = value
                break

    if context is None:
        for value in aliases.values():
            if _context_value(value) in _CONTEXT_ALIASES:
                context = value
                break

    context_name = _context_value(context)
    return _CONTEXT_ALIASES.get(context_name, URI_CONTEXT_RESOURCE)


def _normalize_uri_value(value):
    """Normalizes a URI for protocol and reference classification."""
    normalized_uri = html5lib_shim.convert_entities(value)
    normalized_uri = re.sub(r"[`\000-\040\177-\240\s]+", "", normalized_uri)
    normalized_uri = re.sub(r"[^\x00-\x7f]", "", normalized_uri)
    return normalized_uri.lower()


def _is_protocol_relative_uri(normalized_uri):
    """Returns whether a schemeless URI selects another origin by authority.

    Two or more leading slash/backslash characters begin an authority-like
    reference. WHATWG URL parsing also treats backslashes as separators for
    special schemes and ignores extra leading separators when finding host.
    Python's urlparse does not match that behavior for all of these forms.
    """
    return re.match(r"^[\\/]{2}", normalized_uri) is not None


def _context_allows_protocol_relative(context, options):
    explicit = options.get("allow_protocol_relative")
    if explicit is not None:
        return bool(explicit)

    return context in PROTOCOL_RELATIVE_URI_CONTEXTS


def sanitize_uri_value(
    value,
    allowed_protocols=ALLOWED_PROTOCOLS,
    context=None,
    **kwargs,
):
    """Checks a uri value according to its usage context.

    :arg value: the uri value to sanitize

    :arg allowed_protocols: set of allowed protocols

    :arg context: one of the ``URI_CONTEXT_*`` constants or a descriptive
        alias such as ``"link"``, ``"href"``, ``"resource"``, ``"src"`` or
        ``"style"``

    :returns: allowed value or None

    """
    # Tolerate the alternate plausible argument order
    # sanitize_uri_value(value, "resource", protocols).
    if not isinstance(
        allowed_protocols, (str, frozenset, set, tuple, list, type(None))
    ):
        protocols_candidate = context
        context = allowed_protocols
        allowed_protocols = protocols_candidate
    elif isinstance(allowed_protocols, str):
        if context is None or not isinstance(context, str):
            allowed_protocols, context = context, allowed_protocols

    context = normalize_uri_context(context, **kwargs)

    if kwargs.get("protocols") is not None:
        allowed_protocols = kwargs["protocols"]

    if allowed_protocols is None:
        allowed_protocols = ALLOWED_PROTOCOLS
    allowed_protocols = frozenset(allowed_protocols)

    normalized_uri = _normalize_uri_value(value)

    try:
        parsed = parse_shim.urlparse(normalized_uri)
    except ValueError:
        return None

    if parsed.scheme:
        if parsed.scheme in allowed_protocols:
            return value
        return None

    if normalized_uri.startswith("#"):
        return value

    if ":" in normalized_uri and normalized_uri.split(":")[0] in allowed_protocols:
        return value

    if _is_protocol_relative_uri(normalized_uri):
        if not _context_allows_protocol_relative(context, kwargs):
            return None

    if "http" in allowed_protocols or "https" in allowed_protocols:
        return value

    return None


class Cleaner:
    """Cleaner for cleaning HTML fragments of malicious content

    This cleaner is a security-focused function whose sole purpose is to remove
    malicious content from a string such that it can be displayed as content in
    a web page.

    To use::

        from bleach.sanitizer import Cleaner

        cleaner = Cleaner()

        for text in all_the_yucky_things:
            sanitized = cleaner.clean(text)

    .. Note::

       This cleaner is not designed to use to transform content to be used in
       non-web-page contexts.

    .. Warning::

       This cleaner is not thread-safe--the html parser has internal state.
       Create a separate cleaner per thread!


    """

    def __init__(
        self,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=False,
        strip_comments=True,
        filters=None,
        css_sanitizer=None,
    ):
        """Initializes a Cleaner

        :arg set tags: set of allowed tags; defaults to
            ``bleach.sanitizer.ALLOWED_TAGS``

        :arg dict attributes: allowed attributes; can be a callable, list or dict;
            defaults to ``bleach.sanitizer.ALLOWED_ATTRIBUTES``

        :arg set protocols: set of allowed protocols for links; defaults
            to ``bleach.sanitizer.ALLOWED_PROTOCOLS``

        :arg bool strip: whether or not to strip disallowed elements

        :arg bool strip_comments: whether or not to strip HTML comments

        :arg list filters: list of html5lib Filter classes to pass streamed content through

            .. seealso:: http://html5lib.readthedocs.io/en/latest/movingparts.html#filters

            .. Warning::

               Using filters changes the output of ``bleach.Cleaner.clean``.
               Make sure the way the filters change the output are secure.

        :arg CSSSanitizer css_sanitizer: instance with a "sanitize_css" method for
            sanitizing style attribute values and style text; defaults to None

        """
        self.tags = tags
        self.attributes = attributes
        self.protocols = protocols
        self.strip = strip
        self.strip_comments = strip_comments
        self.filters = filters or []
        self.css_sanitizer = css_sanitizer

        self.parser = html5lib_shim.BleachHTMLParser(
            tags=self.tags,
            strip=self.strip,
            consume_entities=False,
            namespaceHTMLElements=False,
        )
        self.walker = html5lib_shim.getTreeWalker("etree")
        self.serializer = html5lib_shim.BleachHTMLSerializer(
            quote_attr_values="always",
            omit_optional_tags=False,
            escape_lt_in_attrs=True,
            # We want to leave entities as they are without escaping or
            # resolving or expanding
            resolve_entities=False,
            # Bleach has its own sanitizer, so don't use the html5lib one
            sanitize=False,
            # clean preserves attr order
            alphabetical_attributes=False,
        )

        if css_sanitizer is None:
            # FIXME(willkg): this doesn't handle when attributes or an
            # attributes value is a callable
            attributes_values = []
            if isinstance(attributes, list):
                attributes_values = attributes

            elif isinstance(attributes, dict):
                attributes_values = []
                for values in attributes.values():
                    if isinstance(values, (list, tuple)):
                        attributes_values.extend(values)

            if "style" in attributes_values:
                warnings.warn(
                    "'style' attribute specified, but css_sanitizer not set.",
                    category=NoCssSanitizerWarning,
                )

    def clean(self, text):
        """Cleans text and returns sanitized result as unicode

        :arg str text: text to be cleaned

        :returns: sanitized text as unicode

        :raises TypeError: if ``text`` is not a text type

        """
        if not isinstance(text, str):
            message = (
                f"argument cannot be of {text.__class__.__name__!r} type, "
                + "must be of text type"
            )
            raise TypeError(message)

        if not text:
            return ""

        dom = self.parser.parseFragment(text)
        filtered = BleachSanitizerFilter(
            source=self.walker(dom),
            allowed_tags=self.tags,
            attributes=self.attributes,
            strip_disallowed_tags=self.strip,
            strip_html_comments=self.strip_comments,
            css_sanitizer=self.css_sanitizer,
            allowed_protocols=self.protocols,
        )

        # Apply any filters after the BleachSanitizerFilter
        for filter_class in self.filters:
            filtered = filter_class(source=filtered)

        return self.serializer.render(filtered)


def attribute_filter_factory(attributes):
    """Generates attribute filter function for the given attributes value

    The attributes value can take one of several shapes. This returns a filter
    function appropriate to the attributes value. One nice thing about this is
    that there's less if/then shenanigans in the ``allow_token`` method.

    """
    if callable(attributes):
        return attributes

    if isinstance(attributes, dict):

        def _attr_filter(tag, attr, value):
            if tag in attributes:
                attr_val = attributes[tag]
                if callable(attr_val):
                    return attr_val(tag, attr, value)

                if attr in attr_val:
                    return True

            if "*" in attributes:
                attr_val = attributes["*"]
                if callable(attr_val):
                    return attr_val(tag, attr, value)

                return attr in attr_val

            return False

        return _attr_filter

    if isinstance(attributes, list):

        def _attr_filter(tag, attr, value):
            return attr in attributes

        return _attr_filter

    raise ValueError("attributes needs to be a callable, a list or a dict")


class BleachSanitizerFilter(html5lib_shim.SanitizerFilter):
    """html5lib Filter that sanitizes text

    This filter can be used anywhere html5lib filters can be used.

    """

    def __init__(
        self,
        source,
        allowed_tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        allowed_protocols=ALLOWED_PROTOCOLS,
        attr_val_is_uri=html5lib_shim.attr_val_is_uri,
        svg_attr_val_allows_ref=html5lib_shim.svg_attr_val_allows_ref,
        svg_allow_local_href=html5lib_shim.svg_allow_local_href,
        strip_disallowed_tags=False,
        strip_html_comments=True,
        css_sanitizer=None,
    ):
        """Creates a BleachSanitizerFilter instance

        :arg source: html5lib TreeWalker stream as an html5lib TreeWalker

        :arg set allowed_tags: set of allowed tags; defaults to
            ``bleach.sanitizer.ALLOWED_TAGS``

        :arg dict attributes: allowed attributes; can be a callable, list or dict;
            defaults to ``bleach.sanitizer.ALLOWED_ATTRIBUTES``

        :arg set allowed_protocols: set of allowed protocols for links; defaults
            to ``bleach.sanitizer.ALLOWED_PROTOCOLS``

        :arg attr_val_is_uri: set of attributes that have URI values

        :arg svg_attr_val_allows_ref: set of SVG attributes that can have
            references

        :arg svg_allow_local_href: set of SVG elements that can have local
            hrefs

        :arg bool strip_disallowed_tags: whether or not to strip disallowed
            tags

        :arg bool strip_html_comments: whether or not to strip HTML comments

        :arg CSSSanitizer css_sanitizer: instance with a "sanitize_css" method for
            sanitizing style attribute values and style text; defaults to None

        """
        # NOTE(willkg): This is the superclass of
        # html5lib.filters.sanitizer.Filter. We call this directly skipping the
        # __init__ for html5lib.filters.sanitizer.Filter because that does
        # things we don't need to do and kicks up the deprecation warning for
        # using Sanitizer.
        html5lib_shim.Filter.__init__(self, source)

        self.allowed_tags = frozenset(allowed_tags)
        self.allowed_protocols = frozenset(allowed_protocols)

        self.attr_filter = attribute_filter_factory(attributes)
        self.strip_disallowed_tags = strip_disallowed_tags
        self.strip_html_comments = strip_html_comments

        self.attr_val_is_uri = attr_val_is_uri
        self.uri_attribute_names = {
            attribute_name for _, attribute_name in attr_val_is_uri
        } | EXTRA_URI_ATTRIBUTES
        self.svg_attr_val_allows_ref = svg_attr_val_allows_ref
        self.css_sanitizer = css_sanitizer
        self.svg_allow_local_href = svg_allow_local_href
        self._css_sanitize_parameters = self._get_css_sanitize_parameters()

    def _get_css_sanitize_parameters(self):
        if self.css_sanitizer is None:
            return None
        try:
            return inspect.signature(self.css_sanitizer.sanitize_css).parameters
        except (TypeError, ValueError):
            return None

    def sanitize_stream(self, token_iterator):
        for token in token_iterator:
            ret = self.sanitize_token(token)

            if not ret:
                continue

            if isinstance(ret, list):
                yield from ret
            else:
                yield ret

    def merge_characters(self, token_iterator):
        """Merge consecutive Characters tokens in a stream"""
        characters_buffer = []

        for token in token_iterator:
            if characters_buffer:
                if token["type"] == "Characters":
                    characters_buffer.append(token)
                    continue
                else:
                    # Merge all the characters tokens together into one and then
                    # operate on it.
                    new_token = {
                        "data": "".join(
                            [char_token["data"] for char_token in characters_buffer]
                        ),
                        "type": "Characters",
                    }
                    characters_buffer = []
                    yield new_token

            elif token["type"] == "Characters":
                characters_buffer.append(token)
                continue

            yield token

        new_token = {
            "data": "".join([char_token["data"] for char_token in characters_buffer]),
            "type": "Characters",
        }
        yield new_token

    def __iter__(self):
        return self.merge_characters(
            self.sanitize_stream(html5lib_shim.Filter.__iter__(self))
        )

    def sanitize_token(self, token):
        """Sanitize a token either by HTML-encoding or dropping.

        Unlike sanitizer.Filter, allowed_attributes can be a dict of {'tag':
        ['attribute', 'pairs'], 'tag': callable}.

        Here callable is a function with two arguments of attribute name and
        value. It should return true of false.

        Also gives the option to strip tags instead of encoding.

        :arg dict token: token to sanitize

        :returns: token or list of tokens

        """
        token_type = token["type"]
        if token_type in ["StartTag", "EndTag", "EmptyTag"]:
            if token["name"] in self.allowed_tags:
                return self.allow_token(token)

            elif self.strip_disallowed_tags:
                return None

            else:
                return self.disallowed_token(token)

        elif token_type == "Comment":
            if not self.strip_html_comments:
                # call lxml.sax.saxutils to escape &, <, and > in addition to " and '
                token["data"] = html5lib_shim.escape(
                    token["data"], entities={'"': "&quot;", "'": "&#x27;"}
                )
                return token
            else:
                return None

        elif token_type == "Characters":
            return self.sanitize_characters(token)

        else:
            return token

    def sanitize_characters(self, token):
        """Handles Characters tokens

        Our overridden tokenizer doesn't do anything with entities. However,
        that means that the serializer will convert all ``&`` in Characters
        tokens to ``&amp;``.

        Since we don't want that, we extract entities here and convert them to
        Entity tokens so the serializer will let them be.

        :arg token: the Characters token to work on

        :returns: a list of tokens

        """
        data = token.get("data", "")

        if not data:
            return token

        data = INVISIBLE_CHARACTERS_RE.sub(INVISIBLE_REPLACEMENT_CHAR, data)
        token["data"] = data

        # If there isn't a & in the data, we can return now
        if "&" not in data:
            return token

        new_tokens = []

        # For each possible entity that starts with a "&", we try to extract an
        # actual entity and re-tokenize accordingly
        for part in html5lib_shim.next_possible_entity(data):
            if not part:
                continue

            if part.startswith("&"):
                entity = html5lib_shim.match_entity(part)
                if entity is not None:
                    if entity == "amp":
                        # LinkifyFilter can't match urls across token boundaries
                        # which is problematic with &amp; since that shows up in
                        # querystrings all the time. This special-cases &amp;
                        # and converts it to a & and sticks it in as a
                        # Characters token. It'll get merged with surrounding
                        # tokens in the BleachSanitizerfilter.__iter__ and
                        # escaped in the serializer.
                        new_tokens.append({"type": "Characters", "data": "&"})
                    else:
                        new_tokens.append({"type": "Entity", "name": entity})

                    # Length of the entity plus 2--one for & at the beginning
                    # and one for ; at the end
                    remainder = part[len(entity) + 2 :]
                    if remainder:
                        new_tokens.append({"type": "Characters", "data": remainder})
                    continue

            new_tokens.append({"type": "Characters", "data": part})

        return new_tokens

    def uri_context_for_attribute(self, tag, namespaced_name):
        """Returns the URI usage context for a token attribute.

        Navigation attributes keep the historical policy for
        protocol-relative references. Every other URI attribute is treated as
        a resource-loading context, including ``src`` and ``object[data]``.
        """
        namespace, attribute_name = namespaced_name
        normalized_tag = (tag or "").lower()
        normalized_attribute = (attribute_name or "").lower()

        if normalized_attribute == "style":
            return URI_CONTEXT_STYLE

        if normalized_attribute == "href":
            if normalized_tag in RESOURCE_HREF_TAGS:
                return URI_CONTEXT_RESOURCE
            return URI_CONTEXT_NAVIGATION

        if normalized_attribute in NAVIGATION_URI_ATTRIBUTES:
            return URI_CONTEXT_NAVIGATION

        return URI_CONTEXT_RESOURCE

    def sanitize_uri_value(
        self,
        value,
        allowed_protocols=ALLOWED_PROTOCOLS,
        context=None,
        **kwargs,
    ):
        """Checks a uri value to see if it's allowed

        :arg value: the uri value to sanitize
        :arg allowed_protocols: set of allowed protocols
        :arg context: explicit usage context for the URI value

        :returns: allowed value or None

        """
        return sanitize_uri_value(value, allowed_protocols, context, **kwargs)

    def allow_token(self, token):
        """Handles the case where we're allowing the tag"""
        if "data" in token:
            # Loop through all the attributes and drop the ones that are not
            # allowed, are unsafe or break other rules. Additionally, fix
            # attribute values that need fixing.
            #
            # At the end of this loop, we have the final set of attributes
            # we're keeping.
            attrs = {}
            for namespaced_name, val in token["data"].items():
                namespace, name = namespaced_name

                # Drop attributes that are not explicitly allowed
                #
                # NOTE(willkg): We pass in the attribute name--not a namespaced
                # name.
                if not self.attr_filter(token["name"], name, val):
                    continue

                # Drop attributes with uri values that use a disallowed protocol
                # Sanitize attributes with uri values
                is_uri_attribute = (
                    namespaced_name in self.attr_val_is_uri
                    or name in self.uri_attribute_names
                )

                if is_uri_attribute:
                    uri_context = self.uri_context_for_attribute(
                        token["name"], namespaced_name
                    )
                    new_value = self.sanitize_uri_value(
                        val,
                        self.allowed_protocols,
                        context=uri_context,
                    )
                    if new_value is None:
                        continue
                    val = new_value

                # Drop values in svg attrs with non-local IRIs
                if namespaced_name in self.svg_attr_val_allows_ref:
                    new_val = re.sub(r"url\s*\(\s*[^#\s][^)]+?\)", " ", unescape(val))
                    new_val = new_val.strip()
                    if not new_val:
                        continue

                    else:
                        # Replace the val with the unescaped version because
                        # it's a iri
                        val = new_val

                # Drop href and xlink:href attr for svg elements with non-local IRIs
                if (None, token["name"]) in self.svg_allow_local_href:
                    if namespaced_name in [
                        (None, "href"),
                        (html5lib_shim.namespaces["xlink"], "href"),
                    ]:
                        if re.search(r"^\s*[^#\s]", val):
                            continue

                # If it's a style attribute, sanitize it
                if namespaced_name == (None, "style"):
                    if self.css_sanitizer:
                        val = self._sanitize_css(val)
                    else:
                        # FIXME(willkg): if style is allowed, but no
                        # css_sanitizer was set up, then this is probably a
                        # mistake and we should raise an error here
                        #
                        # For now, we're going to set the value to "" because
                        # there was no sanitizer set
                        val = ""

                # At this point, we want to keep the attribute, so add it in
                attrs[namespaced_name] = val

            token["data"] = attrs

        return token

    def _sanitize_css(self, value):
        """Calls the CSS sanitizer while propagating the URI protocol policy."""
        sanitize_css = self.css_sanitizer.sanitize_css
        parameters = self._css_sanitize_parameters
        if parameters is None:
            return sanitize_css(value)

        has_keyword_kwargs = any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )
        if "allowed_protocols" in parameters or has_keyword_kwargs:
            return sanitize_css(
                value,
                allowed_protocols=self.allowed_protocols,
            )
        if "protocols" in parameters:
            return sanitize_css(
                value,
                protocols=self.allowed_protocols,
            )
        return sanitize_css(value)

    def disallowed_token(self, token):
        token_type = token["type"]
        if token_type == "EndTag":
            token["data"] = f"</{token['name']}>"

        elif token["data"]:
            assert token_type in ("StartTag", "EmptyTag")
            attrs = []
            for (ns, name), v in token["data"].items():
                # If we end up with a namespace, but no name, switch them so we
                # have a valid name to use.
                if ns and not name:
                    ns, name = name, ns

                # Figure out namespaced name if the namespace is appropriate
                # and exists; if the ns isn't in prefixes, then drop it.
                if ns is None or ns not in html5lib_shim.prefixes:
                    namespaced_name = name
                else:
                    namespaced_name = f"{html5lib_shim.prefixes[ns]}:{name}"

                # NOTE(willkg): HTMLSerializer escapes attribute values
                # already, so if we do it here (like HTMLSerializer does),
                # then we end up double-escaping.
                attrs.append(f' {namespaced_name}="{v}"')
            token["data"] = f"<{token['name']}{''.join(attrs)}>"

        else:
            token["data"] = f"<{token['name']}>"

        if token.get("selfClosing"):
            token["data"] = f"{token['data'][:-1]}/>"

        token["type"] = "Characters"

        del token["name"]
        return token
