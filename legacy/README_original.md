# Funnel Recon

Ferramenta de reconhecimento competitivo para anúncios do Meta.

## O que tem aqui

- **`PROJETO_funnel_recon.md`** — o brief completo. Leia primeiro. Descreve o
  problema, o que já foi construído, a arquitetura em cascata, os dois tipos de
  cloaker (destino e criativo) e a ordem de construção. É o documento que você
  abre junto com o Claude Code.

- **`cloaker_probe.py`** — motor de teste de acesso (estágio [3] do brief).
  Dispara uma URL com várias personas (TLS + headers + referrer) e diz qual
  camada do cloaker está filtrando. Já funciona sozinho.

- **`adlib-harvester/`** — extensão Chrome (estágio [1] do brief). Coleta todos
  os anúncios de uma página na Biblioteca, agrupa por domínio, detecta
  vazamentos e exporta CSV/JSON. Tem README próprio dentro da pasta.

## Começo rápido

### Probe (precisa de Python 3.10+)
```bash
pip3 install curl_cffi
python3 cloaker_probe.py "https://dominio.com/l/hash?fbclid=..."
```

### Extensão
1. Abra `chrome://extensions`
2. Ative "Modo do desenvolvedor"
3. "Carregar sem compactação" → selecione a pasta `adlib-harvester`
4. Abra a Biblioteca de Anúncios; o painel aparece embaixo à direita

## Próximo passo

Abra este projeto no Claude Code e use o comando sugerido na seção 12 do brief
para começar pelo módulo OSINT.
