"""
Build clickable file links for various git providers.
"""
from urllib.parse import quote
from app.models import GitProviderEnum


def build_git_file_url(
    repo_url: str | None,
    file_path: str | None,
    line_start: int | None = None,
    line_end: int | None = None,
    branch: str | None = None,
    commit_sha: str | None = None,
    provider: GitProviderEnum | None = GitProviderEnum.GITLAB,
) -> str | None:
    """
    Returns a direct URL to the file in the git UI, at the right line.
    
    Supported providers:
      - GitLab:    https://gitlab.com/group/repo/-/blob/main/path/file.py#L10-20
      - GitHub:    https://github.com/org/repo/blob/main/path/file.py#L10-L20
      - Bitbucket: https://bitbucket.org/org/repo/src/main/path/file.py#lines-10
      - Azure:     https://dev.azure.com/org/project/_git/repo?path=/file.py&version=main&line=10
      - Gitea:     https://gitea.example.com/user/repo/src/branch/main/file.py#L10
    """
    if not repo_url or not file_path:
        return None

    repo_url = repo_url.rstrip("/")
    # Use commit SHA if available for exact pinpointing, else branch
    ref = quote(commit_sha or branch or "main", safe="")

    # Normalize file path (remove leading slash) and encode path segments
    fp = "/".join(quote(seg, safe="") for seg in file_path.lstrip("/").split("/"))

    p = provider or GitProviderEnum.GITLAB

    if p == GitProviderEnum.GITLAB:
        url = f"{repo_url}/-/blob/{ref}/{fp}"
        if line_start:
            url += f"#L{line_start}"
            if line_end and line_end != line_start:
                url += f"-{line_end}"

    elif p == GitProviderEnum.GITHUB:
        url = f"{repo_url}/blob/{ref}/{fp}"
        if line_start:
            url += f"#L{line_start}"
            if line_end and line_end != line_start:
                url += f"-L{line_end}"

    elif p == GitProviderEnum.BITBUCKET:
        url = f"{repo_url}/src/{ref}/{fp}"
        if line_start:
            url += f"#lines-{line_start}"

    elif p == GitProviderEnum.AZURE:
        url = f"{repo_url}?path=/{fp}&version=GB{ref}"
        if line_start:
            url += f"&line={line_start}&lineEnd={line_end or line_start}&lineStartColumn=1&lineEndColumn=1"

    elif p == GitProviderEnum.GITEA:
        url = f"{repo_url}/src/branch/{ref}/{fp}"
        if line_start:
            url += f"#L{line_start}"

    else:
        # Generic fallback
        url = f"{repo_url}/blob/{ref}/{fp}"
        if line_start:
            url += f"#L{line_start}"

    return url
