"""Literal infix lookup for drawing numbers in filenames and tag labels."""
import re


# A drawing fragment contains a digit and at least three characters. Keep
# punctuation literal so e.g. 01.01 and 01-01 remain different revisions.
_RUN = re.compile(r'[a-zA-Z0-9._-]+')
_DIGIT = re.compile(r'[0-9]')


def is_number_query(query):
    return len(query) >= 3 and _RUN.fullmatch(query) is not None and _DIGIT.search(query) is not None


def number_grams(name, tags):
    grams = set()
    for text in (name, *tags):
        for match in _RUN.finditer(text):
            token = match.group().lower()
            if _DIGIT.search(token):
                grams.update(token[i:i + 3] for i in range(len(token) - 2))
    return sorted(grams)
