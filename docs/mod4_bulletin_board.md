# Módulo 4: Quadro Público Imutável & Recibos Verificáveis

Documentação técnica das implementações de responsabilidade do **Integrante 4 (Dev D)**: o livro-razão encadeado (*Append-Only Bulletin Board*) e o sistema de emissão e verificação de recibos digitais resistentes à coerção.

## Arquivos do Módulo

| Arquivo | Responsabilidade |
|---|---|
| `src/evoting/bulletin_board.py` | Cálculo de hash SHA-256 dos blocos e verificação de integridade da cadeia |
| `src/evoting/receipt.py` | Emissão de recibos assinados com RSA-PSS pelo servidor e verificação de autenticidade |
| `tests/test_bulletin_board.py` | Suíte de 16 testes unitários (infraestrutura, hash-chain, fraude e recibos) |

---

## 1. Quadro Público Imutável (`src/evoting/bulletin_board.py`)

O quadro público registra todas as cédulas cifradas em uma cadeia linear e pública de blocos (`BulletinBlock`), ancorada no Bloco 0 (Gênesis), cujo `previous_hash` é a constante de 64 zeros (`GENESIS_PREVIOUS_HASH = "0" * 64`).

### `compute_block_hash(...) -> str`

Calcula o digest **SHA-256** (hexadecimal de 64 caracteres) para um bloco $k$:

$$H_k = \text{SHA-256}(H_{k-1} \parallel k \parallel \text{voter\_id} \parallel \text{canonical}(\text{cédula}) \parallel \text{sig} \parallel \text{timestamp})$$

**Como funciona internamente:**
1. **Canonicalização da cédula:** tenta chamar `canonicalize_payload(ballot_data)` (Módulo 1 — Dev A). Enquanto o stub do Módulo 1 lançar `NotImplementedError`, aplica automaticamente o fallback idêntico (`json.dumps(ballot_data, sort_keys=True, separators=(",", ":")).encode("utf-8")`), garantindo que dicionários com chaves em ordens diferentes produzam sempre o mesmo hash.
2. **Prevenção de ambiguidade de delimitadores:** em vez de concatenar strings diretamente (o que poderia causar colisões estruturais como `"v1" + "23"` vs `"v12" + "3"`), os 6 campos ordenados são serializados em um array JSON compacto (`json.dumps([...], separators=(",", ":"))`).
3. **Hashing:** aplica `hashlib.sha256` sobre os bytes UTF-8 resultantes e retorna a string hexadecimal de 64 caracteres.

### `AppendOnlyBulletinBoard.verify_chain_integrity() -> bool`

Audita toda a cadeia em memória (`self.chain`) e retorna `False` ao primeiro sinal de adulteração. Protege contra o cenário de **administrador de banco de dados malicioso** verificando 4 invariantes em sequência:

1. **Cadeia não vazia:** garante que há pelo menos o Bloco Gênesis.
2. **Sequência contínua de índices:** `block.index == expected_index` (detecta exclusão, inserção indevida ou reordenação de blocos).
3. **Continuidade dos elos (`previous_hash`):**
   - No Bloco 0, exige `previous_hash == GENESIS_PREVIOUS_HASH`.
   - Em todo Bloco $k \ge 1$, exige `previous_hash == chain[k - 1].block_hash`.
4. **Integridade do conteúdo:** recalcula `compute_block_hash(...)` com os campos atuais do bloco e confirma que bate exatamente com `block.block_hash` (detecta qualquer alteração em `ballot_data`, `voter_id`, assinatura ou `timestamp`).

---

## 2. Recibos Verificáveis e Resistentes à Coerção (`src/evoting/receipt.py`)

Após o voto ser gravado no quadro público, o servidor emite um `VoterReceipt` assinado com sua chave privada RSA-2048.

### `_build_receipt_message(block_index, block_hash, voter_id) -> bytes`

Função auxiliar interna que padroniza a mensagem determinística assinada e verificada no formato UTF-8:

```text
"{block_index}:{block_hash}:{voter_id}"
```

Centralizar essa formatação garante que `issue_voter_receipt` e `verify_receipt` operem sempre sobre exatamente os mesmos bytes.

### `issue_voter_receipt(block, server_private_key) -> VoterReceipt`

1. Monta a mensagem determinística com `_build_receipt_message`.
2. Assina os bytes com a chave privada do servidor usando **RSA-PSS**, função geradora de máscara **MGF1(SHA-256)**, sal máximo (`padding.PSS.MAX_LENGTH`) e hash **SHA-256**.
3. Retorna um `VoterReceipt` com:
   - `receipt_id`: identificador legível no formato `rcpt_{index}_{block_hash[:8]}`
   - `block_index`, `voter_id`, `block_hash`: metadados públicos do bloco
   - `server_signature_hex`: assinatura RSA-PSS codificada em hexadecimal
   - `issued_at`: timestamp UTC em formato ISO 8601

### `verify_receipt(receipt, server_public_key) -> bool`

1. Reconstrói a mensagem determinística via `_build_receipt_message`.
2. Converte `receipt.server_signature_hex` para bytes com `bytes.fromhex(...)`. Caso a string não seja hexadecimal válida (`ValueError`), retorna `False` sem lançar exceção.
3. Valida a assinatura com `server_public_key.verify(...)` nos mesmos parâmetros RSA-PSS/SHA-256. Retorna `True` se autêntica e `False` caso `InvalidSignature` seja levantada (campos adulterados, assinatura corrompida ou chave pública incorreta).

### Garantia de Resistência à Coerção

O `VoterReceipt` **omite explicitamente** o voto em claro $m$ e o fator de aleatoriedade $r$ do ElGamal. Assim:
- O eleitor consegue verificar individualmente que seu voto foi incluído e permanece inalterado no quadro público (conferindo `block_index` e `block_hash`).
- Um coator ou comprador de votos **não consegue** usar o recibo para descobrir em quem o eleitor votou, pois sem $r$ a cifra ElGamal publicada no bloco permanece indistinguível.

---

## 3. Guia de Integração com os Demais Módulos

### Módulo 1 — Identidade e RSA (Dev A: `src/evoting/crypto/rsa.py`)
- `compute_block_hash` já importa e invoca `canonicalize_payload(ballot_data)`.
- Assim que `canonicalize_payload` for implementada seguindo a especificação (`sort_keys=True`, `separators=(",", ":")`, codificação UTF-8), a integração ocorre automaticamente, sem alterações no Módulo 4 e mantendo os hashes 100% compatíveis.

### Módulo 5 — Auditoria Independente (Dev E: `src/evoting/auditor.py`)
- Na etapa de verificação da continuidade da cadeia de hashes ($H_k'$), recomenda-se importar e reutilizar diretamente `compute_block_hash` para evitar qualquer divergência de serialização:

```python
from evoting.bulletin_board import compute_block_hash
```

- Exemplo de recomputação a partir de um bloco público (dicionário exportado via `export_chain_json()` ou carregado do SQLite):

```python
recomputed_hash = compute_block_hash(
    previous_hash=block["previous_hash"],
    index=block["index"],
    voter_id=block["voter_id"],
    ballot_data=block["ballot_data"],
    voter_signature_hex=block["voter_signature_hex"],
    timestamp=block["timestamp"],
)
assert recomputed_hash == block["block_hash"]
```

### Pipeline Principal (`bin/election_cli.py`)
- **Etapa 3 (Votação e Recibos):** grava cada cédula no quadro público com hash SHA-256 real e valida os recibos assinados pelo servidor (`Coercion-Resistant Signed Receipt Valid: True`).
- **Etapa 5 (Detecção de Adulteração):** simula um administrador malicioso alterando o Bloco #1 e confirma a detecção imediata (`Bulletin Board Chain Verification Result: False`).

---

## 4. Comandos para Ambiente, Integração e Validação

### 4.1. Preparação do Ambiente Virtual

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e ".[dev]"
```

**Linux / macOS (Bash):**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"
```

### 4.2. Como Integrar esta Branch (`RuteDevD`) no Git

Para atualizar sua branch local com o código do Módulo 4 e testar a integração com a sua parte:

```bash
# Baixar as referências atualizadas do repositório remoto
git fetch origin

# Opção A: testar a branch do Módulo 4 diretamente
git checkout RuteDevD
git pull origin RuteDevD

# Opção B: trazer o Módulo 4 para dentro da sua branch de desenvolvimento
git checkout <sua-branch>
git merge origin/RuteDevD
```

### 4.3. Testes Unitários e Cobertura

```bash
# Rodar apenas os testes do Módulo 4 com relatório de linhas descobertas
pytest tests/test_bulletin_board.py --cov=src/evoting/bulletin_board --cov=src/evoting/receipt --cov-report=term-missing --cov-fail-under=80

# Rodar toda a suíte de integração do projeto (exige cobertura global >= 80%)
pytest
```

### 4.4. Formatação e Análise Estática (Linters)

```bash
# Formatar automaticamente (Ruff)
ruff format src/evoting/bulletin_board.py src/evoting/receipt.py tests/test_bulletin_board.py

# Checar regras de estilo no Módulo 4 ou no projeto inteiro
ruff check src/evoting/bulletin_board.py src/evoting/receipt.py tests/test_bulletin_board.py
ruff check .

# Análise estática (Pylint)
pylint src/evoting/bulletin_board.py src/evoting/receipt.py
pylint src/evoting
```

### 4.5. Execução Integrada (CLI, Auditoria e Documentação)

```bash
# Rodar a demonstração das 8 etapas da eleição (valida Etapas 3 e 5 do Módulo 4)
python bin/election_cli.py

# Rodar a auditoria independente (Confiança Zero)
python bin/audit_cli.py
python bin/audit_cli.py --db-path /caminho/para/eleicao.db
python bin/audit_cli.py --board-json /caminho/para/board_dump.json --export-report relatorio.json

# Inicializar banco SQLite local manualmente
python -c "from evoting.storage.database import init_db; init_db()"

# Gerar build local da documentação técnica (MkDocs)
mkdocs build
```

*(Observação: em ambientes Linux/macOS com `make` instalado, os comandos equivalentes estão disponíveis no `Makefile`: `make test`, `make lint`, `make format`, `make run-demo`, `make run-audit` e `make docs-build`.)*

---

## 5. Resumo dos Testes e Métricas Validadas

A suíte `tests/test_bulletin_board.py` reúne **16 testes** distribuídos em 3 classes:

* **`TestBulletinBoardInfrastructure`:** serialização de blocos, persistência em SQLite e estrutura do recibo.
* **`TestBulletinBoardHashChain`:** formato SHA-256, determinismo de canonicalização, efeito avalanche em todos os 6 campos, detecção de adulteração de cédula/assinatura/timestamp, quebra de elo/Gênesis, exclusão/reordenação de blocos e ciclo `export_chain_json` / `load_from_list`.
* **`TestVoterReceipts`:** emissão e verificação válida, omissão de `r` e `m`, serialização `from_dict`, adulteração de campos, chave pública incorreta e assinatura corrompida ou não-hexadecimal.

| Verificação | Resultado Validado |
|---|---|
| `pytest` (projeto inteiro) | 49/49 passando — cobertura global **87,30%** |
| Cobertura `src/evoting/receipt.py` | **100%** |
| Cobertura `src/evoting/bulletin_board.py` | **95%** *(5% restantes são os `except NotImplementedError` do fallback)* |
| `pylint` (`bulletin_board.py` + `receipt.py`) | **10.00/10** |
| `ruff check` | **0 erros** |