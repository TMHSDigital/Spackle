import logging
import subprocess

log = logging.getLogger("runner")


class CommandFailed(Exception):
    def __init__(self, returncode, stderr):
        super().__init__(f"command exited with {returncode}")
        self.returncode = returncode
        self.stderr = stderr


def run(command, cwd=None, timeout=30):
    log.info("running job in %s", cwd or ".")
    proc = subprocess.run(command, shell=True, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        log.warning("job failed with status %s", proc.returncode)
        raise CommandFailed(proc.returncode, proc.stderr)
    return proc.stdout
