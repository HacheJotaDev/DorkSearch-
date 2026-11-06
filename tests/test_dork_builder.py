import pytest

from app.search.dork_builder import (
    PRESETS, DorkBuilder, DorkSpec, build_query, dorks_from_presets,
    generate_matrix, load_dorks_file,
)


def test_operadores_basicos():
    q = DorkBuilder().site("example.com").inurl("product.php?id=").filetype("php").build()
    assert "site:example.com" in q
    assert "inurl:product.php?id=" in q
    assert "filetype:php" in q


def test_intitle_intext_exclude():
    q = DorkBuilder().intitle("login").intext("password").exclude("wordpress").build()
    assert "intitle:login" in q
    assert "intext:password" in q
    assert "-wordpress" in q


def test_multiples_sites_con_or():
    q = build_query(DorkSpec(site=["a.com", "b.com"]))
    assert "(site:a.com OR site:b.com)" in q


def test_exclusion_frase_entre_comillas():
    q = build_query(DorkSpec(exclude=["some phrase"]))
    assert '-"some phrase"' in q


def test_preset_php_id():
    q = build_query(PRESETS["php_id"])
    assert "inurl:.php?id=" in q


def test_presets_disponibles():
    names = dorks_from_presets(["php_id", "asp_id", "paneles_admin"])
    assert len(names) == 3
    assert all(isinstance(n, str) and n for n in names)


def test_preset_desconocido():
    with pytest.raises(KeyError):
        dorks_from_presets(["no_existe"])


def test_generate_matrix_combina_tokens():
    qs = generate_matrix(DorkSpec(site=["s.com"]), ["id=", "item="], ["php"])
    assert len(qs) == 2
    assert all("site:s.com" in q and "filetype:php" in q for q in qs)
    assert any("inurl:id=" in q for q in qs)
    assert any("inurl:item=" in q for q in qs)


def test_load_dorks_file(tmp_path):
    f = tmp_path / "dorks.txt"
    f.write_text("# comentario\nsite:a.com inurl:id=\n\nsite:b.com\n", encoding="utf-8")
    assert load_dorks_file(f) == ["site:a.com inurl:id=", "site:b.com"]


def test_load_dorks_file_inexistente():
    with pytest.raises(FileNotFoundError):
        load_dorks_file("/no/existe/dorks.txt")
