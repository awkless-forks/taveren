# SPDX-FileCopyrightText: 2026 Jason Pena <jpalex@nmsu.edu>
# SPDX-License-Identifier: BSD-2-Clause

"""Sphinx configuration for the Ta'veren documentation."""

import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

with open(ROOT / "pyproject.toml", "rb") as f:
    _project = tomllib.load(f)["project"]

# -- Project information -----------------------------------------------------

project = "Ta'veren"
author = "Ta'veren contributors"
copyright = "2026, " + author
release = _project["version"]
version = ".".join(release.split(".")[:2])

# -- General configuration ---------------------------------------------------

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- autodoc / autosummary ---------------------------------------------------

autosummary_generate = True
autosummary_imported_members = False
autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
    "member-order": "bysource",
}
autodoc_typehints = "description"
autodoc_class_signature = "separated"

# -- intersphinx -------------------------------------------------------------

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "angr": ("https://docs.angr.io/en/latest/", None),
    "networkx": ("https://networkx.org/documentation/stable/", None),
}

# -- HTML output -------------------------------------------------------------

html_theme = "furo"
html_title = f"Ta'veren {release}"
html_static_path = ["_static"]
