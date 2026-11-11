"""theHarvester: subdomains, emails and IPs from a locally installed binary."""

from __future__ import annotations

import asyncio
import contextlib
import html
import json
import re
import shutil
import tempfile
from pathlib import Path

from ..models import Entity, EntityType
from ..registry import Module, register
from ..validators import is_valid_email, is_valid_hostname, normalize_ip

# Emails only, not arbitrary text: stdout carries the tool's own banner (which
# includes its author's address), so the XML report is the safe fallback.
_EMAIL_TAG = re.compile(r"<email>(.*?)</email>", re.IGNORECASE | re.DOTALL)


@register
class TheHarvester(Module):
    name = "theharvester"
    accepts = frozenset({EntityType.DOMAIN})
    produces = frozenset({EntityType.SUBDOMAIN, EntityType.EMAIL, EntityType.IP})
    # Shelling out is expensive; keep parallel domains gentle on data sources.
    rate_limit = 0.5
    description = "theHarvester subdomains, emails and IPs (requires local binary)"

    async def run(self, entity, ctx):
        settings = ctx.settings
        binary = shutil.which(settings.theharvester_bin or "theHarvester")
        if binary is None:
            raise RuntimeError(
                "theHarvester not found; install it or set CONIUGATA_THEHARVESTER_BIN"
            )

        domain = entity.value.strip().lower().rstrip(".")
        sources = ",".join(
            part.strip()
            for part in settings.theharvester_sources.split(",")
            if part.strip()
        )
        if not sources:
            raise RuntimeError("CONIUGATA_THEHARVESTER_SOURCES is empty")

        with tempfile.TemporaryDirectory(prefix="coniugata-th-") as tmp:
            base = Path(tmp) / "report"
            cmd = [
                binary,
                "-d",
                domain,
                "-b",
                sources,
                "-l",
                str(settings.theharvester_limit),
                "-f",
                str(base),
                "-q",
            ]
            ctx.log.debug("running %s", " ".join(cmd))
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=settings.theharvester_timeout
                )
            except TimeoutError:
                # Never leave an orphaned harvest running past the scan.
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
                raise RuntimeError(
                    "theHarvester timed out after "
                    f"{settings.theharvester_timeout:g}s on {domain}"
                ) from None

            stdout = stdout_b.decode("utf-8", "replace")
            stderr = stderr_b.decode("utf-8", "replace")
            data = self._load_report(
                Path(str(base) + ".json"), stdout, stderr, proc.returncode, ctx
            )

            # JSON only includes "emails" when some were found, so fall back to
            # the XML report, which always lists them.
            emails = {
                str(item).strip().lower()
                for item in (data.get("emails") or [])
                if str(item).strip()
            }
            xml_report = Path(str(base) + ".xml")
            if xml_report.exists():
                xml_text = xml_report.read_text(encoding="utf-8", errors="replace")
                emails.update(
                    html.unescape(match).strip().lower()
                    for match in _EMAIL_TAG.findall(xml_text)
                )

            for email in sorted(emails):
                if not is_valid_email(email):  # drop malformed report values
                    continue
                yield Entity(
                    type=EntityType.EMAIL,
                    value=email,
                    source=self.name,
                    parent=entity.value,
                    confidence=0.7,
                )

            seen_hosts: set[str] = set()
            seen_ips: set[str] = set()
            for entry in data.get("hosts") or []:
                host, _, ip_part = str(entry).strip().partition(":")
                host = host.strip().lower().rstrip(".")
                ip_part = ip_part.strip()

                # Wildcards only describe a DNS zone, not a real host.
                if not host or host.startswith("*."):
                    continue
                ip = normalize_ip(ip_part) if ip_part else None

                if not ip_part:  # IP-only entry
                    if ip is not None and ip not in seen_ips:
                        seen_ips.add(ip)
                        yield self._ip(ip, entity.value)
                    continue

                if not is_valid_hostname(host):
                    continue
                # Keep results scoped to the queried domain.
                if host != domain and not host.endswith("." + domain):
                    continue

                if host != domain and host not in seen_hosts:
                    seen_hosts.add(host)
                    yield Entity(
                        type=EntityType.SUBDOMAIN,
                        value=host,
                        source=self.name,
                        parent=entity.value,
                        confidence=0.75,
                        raw={"ip": ip} if ip else {},
                    )
                if ip is not None and ip not in seen_ips:
                    seen_ips.add(ip)
                    yield self._ip(ip, host)

    def _ip(self, value: str, parent: str) -> Entity:
        return Entity(
            type=EntityType.IP,
            value=value,
            source=self.name,
            parent=parent,
            confidence=0.7,
        )

    @staticmethod
    def _load_report(
        report: Path, stdout: str, stderr: str, returncode: int, ctx
    ) -> dict:
        if report.exists():
            try:
                loaded = json.loads(
                    report.read_text(encoding="utf-8", errors="replace")
                )
            except (OSError, ValueError) as exc:
                ctx.log.warning("could not parse theHarvester report: %s", exc)
                return {}
            return loaded if isinstance(loaded, dict) else {}
        if returncode:
            detail = stderr.strip()[-300:] or "no error output"
            raise RuntimeError(f"theHarvester exited {returncode}: {detail}")
        ctx.log.debug("theHarvester produced no JSON report")
        return {}
