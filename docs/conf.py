# Sphinx configuration for the oidc-ssh-ca documentation.

project = "oidc-ssh-ca"
copyright = "2026, Atsuo Ishimoto"
author = "Atsuo Ishimoto"

extensions = [
    "myst_parser",
]

myst_enable_extensions = [
    "colon_fence",
]

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "collapse_navigation": False,
    "navigation_depth": 3,
}
