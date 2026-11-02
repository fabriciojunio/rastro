"""Download de conjuntos de dados, só por HTTPS e só aceito com o SHA-256 conferido."""

import hashlib
import urllib.request
from pathlib import Path

_BLOCO = 1024 * 1024
# O NIST SARD responde 403 ao agente padrão do Python. Um agente que diz quem
# está baixando é aceito, e é o educado de qualquer forma.
AGENTE = "rastro/0.1 (+https://github.com/fabriciojunio/rastro)"


class ErroDeUso(Exception):
    """Entrada inválida ou arquivo que não confere: a mensagem é para quem rodou o comando."""


def conferir_hash(arquivo: Path, esperado: str) -> None:
    resumo = hashlib.sha256()
    with arquivo.open("rb") as entrada:
        while bloco := entrada.read(_BLOCO):
            resumo.update(bloco)
    if resumo.hexdigest() != esperado:
        raise ErroDeUso(
            f"o SHA-256 de {arquivo} não confere: esperado {esperado}, obtido {resumo.hexdigest()}"
        )


def baixar(url: str, destino: Path, sha256: str) -> None:
    """Baixa para um arquivo temporário e só renomeia depois de conferir o hash."""
    if not url.startswith("https://"):
        raise ErroDeUso("o download só é feito por HTTPS")
    destino.parent.mkdir(parents=True, exist_ok=True)
    parcial = destino.with_suffix(destino.suffix + ".parcial")
    pedido = urllib.request.Request(url, headers={"User-Agent": AGENTE})  # noqa: S310
    with urllib.request.urlopen(pedido, timeout=120) as resposta, parcial.open("wb") as saida:  # noqa: S310
        while bloco := resposta.read(_BLOCO):
            saida.write(bloco)
    try:
        conferir_hash(parcial, sha256)
    except ErroDeUso:
        parcial.unlink()
        raise
    parcial.replace(destino)
