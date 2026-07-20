"""Static source secret scan — precision over recall (a false positive wrongly penalizes a submission)."""
from hacklet_runner.pipeline import _source_secret_outcome
from hacklet_runner.secretscan import scan_secrets


def _mk(root, files: dict):
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def test_catches_provider_secrets(tmp_path):
    # realistic high-entropy key bodies (mixed case + digits) — a real sk-/sk_live_/ghp_ key is never all
    # one lowercase char, and the openai-key pattern now REQUIRES that entropy to avoid kebab-case FPs.
    _mk(tmp_path, {"a.py": 'o="sk-proj-%s"\ns="sk_live_%s"\ng="ghp_%s"\n'
                   % ("aB3dE7fG" * 6, "b" * 20, "c" * 36)})
    kinds = {f.kind for f in scan_secrets(tmp_path)}
    assert {"openai-key", "stripe-secret", "github-pat"} <= kinds


def test_openai_key_pattern_ignores_kebab_case_lookalikes(tmp_path):
    # the SpinKit / locale FP: kebab-case identifiers sharing the sk- prefix are NOT keys (all-lowercase
    # words, or no digit) — they must not fire, while a real mixed-entropy key alongside them still does.
    _mk(tmp_path, {"ui.css": ".sk-cube-inner-wrapper-item{}\n.sk-chase-dot-before-animation-delay{}\n",
                   "i18n.js": 'const loc="sk-SK-u-ca-gregory-nu-latn-x-long";\n',
                   "real.js": 'const k="sk-proj-%s";\n' % ("Xy7Zq2Wv" * 6)})
    kinds = {f.kind for f in scan_secrets(tmp_path)}
    assert "openai-key" in kinds                                        # the genuine key still fires
    assert sum(f.kind == "openai-key" for f in scan_secrets(tmp_path)) == 1   # exactly one — no kebab FPs


def test_catches_hardcoded_db_password(tmp_path):
    _mk(tmp_path, {"cfg.py": 'DB_PASSWORD = "Sup3rSecretP@ss1234"\n'})
    fs = scan_secrets(tmp_path)
    assert any(f.kind.startswith("hardcoded-") for f in fs)


def test_skips_placeholders_and_env_refs(tmp_path):
    _mk(tmp_path, {"cfg.py": 'API_KEY="your-api-key-here"\nSECRET=os.environ["S"]\n'
                             'TOKEN="${TOKEN}"\nPASSWORD="changeme"\n'})
    assert scan_secrets(tmp_path) == []


def test_skips_aws_docs_example_key(tmp_path):
    _mk(tmp_path, {"cfg.py": 'aws = "AKIAIOSFODNN7EXAMPLE"\n'})  # AWS's documented placeholder
    assert scan_secrets(tmp_path) == []


def test_skips_vendored_dirs_lockfiles_and_example_configs(tmp_path):
    _mk(tmp_path, {"node_modules/x.js": 't="ghp_%s"\n' % ("a" * 36),
                   "poetry.lock": 'k="ghp_%s"\n' % ("b" * 36),
                   ".env.example": 'SECRET="sk_live_%s"\n' % ("c" * 20)})
    assert scan_secrets(tmp_path) == []


def test_value_is_masked(tmp_path):
    _mk(tmp_path, {"a.py": 'k="sk_live_%s"\n' % ("b" * 20)})
    snip = scan_secrets(tmp_path)[0].snippet
    assert "…" in snip and "sk_live_bbbb" not in snip   # masked, not the full secret


def test_scan_accepts_a_single_file(tmp_path):
    p = tmp_path / "only.py"
    p.write_text('k="ghp_%s"\n' % ("a" * 36))
    fs = scan_secrets(p)
    assert len(fs) == 1 and fs[0].file == "only.py"


def test_source_secret_outcome_folds_in_or_clean(tmp_path):
    (tmp_path / "app.py").write_text('k="sk_live_%s"\n' % ("b" * 20))
    o = _source_secret_outcome(tmp_path)
    assert o.outcome == "slop_detected" and o.penalty == 35 and o.category == "hardcoded-secrets"
    assert o.evidence["secrets_found"] == 1
    (tmp_path / "app.py").write_text('k = os.environ["K"]\n')   # now clean
    clean = _source_secret_outcome(tmp_path)
    assert clean.outcome == "clean" and clean.penalty == 0
