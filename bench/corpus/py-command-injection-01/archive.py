EXPORT_ROOT = "/srv/exports"
COMPRESSORS = {"gz": "-czf", "bz2": "-cjf", "xz": "-cJf"}


def compressor_flag(fmt):
    return COMPRESSORS.get(fmt, COMPRESSORS["gz"])


def archive_name(project, fmt):
    suffix = fmt if fmt in COMPRESSORS else "gz"
    return f"{project}.tar.{suffix}"


def build_archive_command(project, fmt="gz"):
    flag = compressor_flag(fmt)
    target = f"{EXPORT_ROOT}/{archive_name(project, fmt)}"
    source = f"projects/{project}"
    return f"tar {flag} {target} {source}"


def describe(project, fmt="gz"):
    return {"project": project, "archive": archive_name(project, fmt), "root": EXPORT_ROOT}
