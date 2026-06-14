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

# Auto-generate anchors for h1-h3 so pages can link to their own sections.
myst_heading_anchors = 3

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# Override footer.html to add a footer "Edit on GitHub" link (visible on mobile).
templates_path = ["_templates"]

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "collapse_navigation": False,
    "navigation_depth": 3,
}

# Show "Edit on GitHub" links on every page (sphinx_rtd_theme).
html_context = {
    "display_github": True,
    "github_user": "atsuoishimoto",
    "github_repo": "oidc-ssh-ca",
    "github_version": "main",
    "conf_py_path": "/docs/",
}
