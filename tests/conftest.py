import hashlib
import zipfile
from pathlib import Path

import pytest

# Zip no formato da Juliet, só para teste: duas CWEs, duas famílias, quatro fluxos.
MODELO_DE_CASO = """
public class {classe} extends AbstractTestCase {{
    public void bad() throws Throwable {{
        {abre} String data = fonte{familia}(); r.{perigoso}("a" + data); }}
    }}
    private void goodG2B() throws Throwable {{
        {abre} String data = "fixo"; r.{perigoso}("a" + data); }}
    }}
    private void goodB2G() throws Throwable {{
        {abre} String data = fonte{familia}(); r.{seguro}(data); r.limpar(data); }}
    }}
}}
"""
ABERTURAS = ("if (IO.t) {", "while (k > 0) {", "if (IO.f()) {", "for (int i = 0; i < 1; i++) {")
SINKS = {"CWE89_SQL": ("execute", "prepareStatement"), "CWE78_OS": ("exec", "escapar")}


def criar_juliet(tmp_path: Path) -> tuple[Path, str]:
    caminho = tmp_path / "juliet.zip"
    with zipfile.ZipFile(caminho, "w") as pacote:
        for prefixo, (perigoso, seguro) in SINKS.items():
            for familia in (1, 2):
                for fluxo in (1, 2, 3, 4):
                    classe = f"{prefixo}__f{familia}_{fluxo:02d}"
                    nome = f"Java/src/testcases/{prefixo}/s01/{classe}.java"
                    pacote.writestr(
                        nome,
                        MODELO_DE_CASO.format(
                            classe=classe,
                            abre=ABERTURAS[fluxo - 1],
                            familia=familia,
                            perigoso=perigoso,
                            seguro=seguro,
                        ),
                    )
    return caminho, hashlib.sha256(caminho.read_bytes()).hexdigest()


@pytest.fixture
def juliet(tmp_path: Path) -> tuple[Path, str]:
    """Zip sintético no formato da Juliet e o SHA-256 dele."""
    return criar_juliet(tmp_path)
