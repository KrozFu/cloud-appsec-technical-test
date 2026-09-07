"""El Markdown es lo que se pega en la documentación del Secure SDLC."""

from threat_agent.render import render_markdown


def test_la_tabla_sale_ordenada_por_riesgo(make_threat, make_model):
    md = render_markdown(make_model([
        make_threat(1, 1, component="Baja"),
        make_threat(5, 5, component="Alta"),
        make_threat(3, 3, component="Media"),
        make_threat(2, 2, component="Otra"),
        make_threat(4, 1, component="Cuarta"),
    ]))
    assert md.index("| 1 | Alta") < md.index("| 5 | Baja")


def test_las_barras_verticales_no_rompen_la_tabla(make_threat, make_model):
    """Un componente llamado 'a|b' partiría la fila en dos columnas."""
    tm = make_model([make_threat(3, 3, component="a|b")] + [make_threat(1, 1) for _ in range(4)])
    fila = next(line for line in render_markdown(tm).splitlines() if "a\\|b" in line)
    # Se cuentan los separadores reales: la barra escapada no abre columna.
    assert fila.replace("\\|", "").count("|") == 9  # 8 columnas => 9 separadores


def test_el_markdown_advierte_de_que_es_un_borrador(make_threat, make_model):
    """El agente asiste, no decide: tiene que decirlo en su propia salida."""
    md = render_markdown(make_model([make_threat(3, 3) for _ in range(5)])).lower()
    assert "borrador" in md and "revisión" in md


def test_se_muestran_las_dos_justificaciones_de_cada_amenaza(make_threat, make_model):
    """Impacto y probabilidad se justifican por separado; es lo que revisa el analista."""
    md = render_markdown(make_model([make_threat(3, 3) for _ in range(5)]))
    assert md.count("**Impacto 3:**") == 5
    assert md.count("**Probabilidad 3:**") == 5
