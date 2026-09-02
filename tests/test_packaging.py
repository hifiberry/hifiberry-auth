"""The packaged licence must say what the repository's licence says."""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
COPYRIGHT = ROOT / "debian" / "copyright"
LICENSE = ROOT / "LICENSE"


def _standalone_license_body(text: str) -> str:
    """Return DEP-5's standalone `License:` paragraph body, unwrapped.

    The format indents the licence text by one space and writes blank lines as
    a lone ' .', so reversing both gives the original back. The standalone
    paragraph is the one carrying that indented body: the short `License:`
    reference inside a `Files:` stanza has nothing under it. Requiring exactly
    one such paragraph keeps this unambiguous -- if a second licence is ever
    added, this says so rather than silently picking one.
    """
    lines = text.rstrip("\n").split("\n")
    starts = [
        i for i, line in enumerate(lines)
        if line.startswith("License:")
        and i + 1 < len(lines)
        and lines[i + 1].startswith(" ")
    ]
    assert len(starts) == 1, (
        f"expected exactly one License: paragraph with a body in "
        f"debian/copyright, found {len(starts)}"
    )
    body = []
    for line in lines[starts[0] + 1:]:
        if line == " .":
            body.append("")
        elif line.startswith(" "):
            body.append(line[1:])
        else:
            break
    return "\n".join(body).strip("\n")


def _field(text: str, name: str) -> str:
    for line in text.split("\n"):
        if line.startswith(f"{name}:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"debian/copyright has no {name}: field")


def test_packaged_licence_text_matches_the_license_file():
    """debian/copyright is static, so nothing but this stops the two diverging.

    lintian only checks that a copyright file exists, not that it is true.
    """
    licence = LICENSE.read_text().rstrip("\n").split("\n")
    assert licence[0].strip() == "MIT License", licence[0]
    expected = "\n".join(licence[1:]).strip("\n")

    assert _standalone_license_body(COPYRIGHT.read_text()) == expected, (
        "the licence text in debian/copyright no longer matches LICENSE"
    )


def test_packaged_copyright_holder_matches_the_license_file():
    """The machine-readable `Copyright:` field is what scanners read.

    It sits outside the licence paragraph, so bumping a year in LICENSE and in
    that paragraph would leave this field stale without this check.
    """
    holders = [l for l in LICENSE.read_text().split("\n")
               if l.startswith("Copyright (c) ")]
    assert holders, "LICENSE has no 'Copyright (c) ' line"
    expected = holders[0][len("Copyright (c) "):].strip()

    assert _field(COPYRIGHT.read_text(), "Copyright") == expected, (
        "debian/copyright's Copyright: field no longer matches LICENSE"
    )


def test_packaged_licence_identifier_matches_the_license_file():
    """The short name is what scanners key on, and it sits outside the body.

    A relicensing that rewrote both licence texts but left these lines saying
    MIT would ship a package whose identifier contradicts its own text --
    the same gap the Copyright: field has, in the other direction.
    """
    first = LICENSE.read_text().split("\n")[0].strip()
    assert first.endswith(" License"), first
    expected = first[: -len(" License")]

    declared = [line.split(":", 1)[1].strip()
                for line in COPYRIGHT.read_text().split("\n")
                if line.startswith("License:")]
    assert declared, "debian/copyright has no License: line"
    assert set(declared) == {expected}, (
        f"debian/copyright declares {sorted(set(declared))} "
        f"but LICENSE is {expected}"
    )
