import ssl

from agenticwf_auth_cli import tls


def _subjects(context):
    return {dict(x[0] for x in c["subject"]).get("commonName") for c in context.get_ca_certs()}


def test_cern_cas_are_added_to_the_systems(monkeypatch):
    monkeypatch.delenv("AGENTICWF_CA_BUNDLE", raising=False)
    names = _subjects(tls.ssl_context())
    assert {"CERN Root Certification Authority 2", "CERN Grid Certification Authority"} <= names
    assert _subjects(ssl.create_default_context()) <= names     # never instead of the system's


def test_extra_bundle_from_the_environment(tmp_path, monkeypatch):
    bundle = tmp_path / "site.pem"
    bundle.write_text(tls.ca_files()[0].read_text())
    monkeypatch.setenv("AGENTICWF_CA_BUNDLE", str(bundle))
    assert "CERN Grid Certification Authority" in _subjects(tls.ssl_context())
