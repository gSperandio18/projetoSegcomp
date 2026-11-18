# Sistema de Votação Eletrônica Auditável e Segura (SegComp 2026)

[![CI & Quality Assurance](https://github.com/projetoSegcomp/actions/workflows/ci.yml/badge.svg)](https://github.com/projetoSegcomp/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Coverage: >=80%](https://img.shields.io/badge/coverage-%3E%3D80%25-green.svg)](https://pytest-cov.readthedocs.io/)

Projeto prático desenvolvido para a disciplina de **Segurança Computacional (SegComp)**.  
**Prazo Final de Entrega:** 23 de Novembro de 2026.

---

## 1. Visão Geral do Projeto

Este projeto consiste em um sistema de votação eletrônica de ponta a ponta verificável (*End-to-End Verifiable E-Voting System*). O sistema garante simultaneamente:

1. **Sigilo Absoluto do Voto:** Cédulas são cifradas utilizando Cifração Homomórfica Exponencial ElGamal. Nenhuma autoridade ou administrador consegue decifrar votos individuais.
2. **Autenticidade e Não-Repúdio:** Eleitores autenticam suas cédulas com chaves privadas RSA-2048 utilizando assinaturas digitais com preenchimento probabilístico (RSA-PSS) e SHA-256.
3. **Confiança Distribuída sem Ponto Único de Falha:** Uma cerimônia de Geração de Chaves Distribuída (DKG) entre no mínimo 3 autoridades eleitorais gera uma chave pública conjunta. A decifração exige a cooperação de todas as autoridades, impedindo decifração unilateral.
4. **Quadro Público Imutável (*Append-Only Bulletin Board*):** Todas as cédulas aceitas são registradas em um livro-razão público encadeado por hashes SHA-256 (Merkle-like chain). Qualquer tentativa de alterar um voto antigo quebra a integridade da cadeia e é imediatamente detectada.
5. **Resistência à Coerção:** Recibos emitidos aos eleitores comprovam a inclusão de sua cédula no quadro público, mas **omitem explicitamente** a aleatoriedade $r$ e o voto em claro $m$, impedindo venda de votos ou coação.
6. **Auditoria Independente de Confiança Zero:** Qualquer cidadão ou auditor externo pode recomputar os produtos homomórficos e verificar todas as assinaturas e hashes utilizando exclusivamente dados públicos via linha de comando (`bin/audit_cli.py`).

---

## 2. Arquitetura Criptográfica e Divisão em 5 Módulos

O código-fonte em `src/evoting/` está estritamente estruturado em 5 módulos de igual complexidade técnica:

```
src/evoting/
├── config/params.py         # Constantes RFC 3526 MODP-2048 (p, g) e limites
├── crypto/
│   ├── modular.py           # Aritmética modular (mod_pow, mod_inverse, secrets)
│   ├── rsa.py               # Módulo 1: Chaves RSA-2048, PSS, Canonicalização
│   ├── elgamal.py           # Módulo 2: Exponential ElGamal & Multiplicação Homomórfica
│   └── dkg.py               # Módulo 3: DKG, Chave Conjunta, Fatias de Decifração
├── storage/database.py      # Camada de Persistência SQLite & SQLAlchemy 2.0 ORM
├── voter.py                 # Módulo 1: Entidade Eleitor & Registro
├── ballot.py                # Módulo 2: Contêineres de Cédulas Multicandidato
├── authority.py             # Módulo 3: Entidade Autoridade Eleitoral & Coordenação
├── bulletin_board.py        # Módulo 4: Quadro Público & Encadeamento de Hash SHA-256
├── receipt.py               # Módulo 4: Recibos Digitais Resistentes à Coerção
├── server.py                # Núcleo Compartilhado: Servidor Eleitoral Central
└── auditor.py               # Módulo 5: Motor de Auditoria Independente
```

### Divisão de Responsabilidades:
- **Módulo 1 (`crypto/rsa.py`, `voter.py`):** Identidade do eleitor, geração de chaves RSA-2048, canonicalização JSON determinística, assinatura e verificação RSA-PSS com SHA-256, e controle de unicidade.
- **Módulo 2 (`crypto/elgamal.py`, `ballot.py`):** Cifração Exponencial ElGamal para votos binários $m \in \{0, 1\}$, onde $(c_1, c_2) = (g^r \bmod p, g^m \cdot h^r \bmod p)$, amostragem CSPRNG de $r \in [2, p-2]$, guardrail contra injeção de votos múltiplos e produto homomórfico.
- **Módulo 3 (`crypto/dkg.py`, `authority.py`):** Cerimônia DKG com $N \ge 3$ autoridades ($x_i \in [2, p-2]$, $h_i = g^{x_i} \bmod p$), síntese da chave conjunta $h = \prod h_i \bmod p$, fatias parciais de decifração $D_i = C_1^{x_i} \bmod p$, inverso modular e resolução de logaritmo discreto limitado para apuração.
- **Módulo 4 (`bulletin_board.py`, `receipt.py`):** Quadro público de avisos imutável com encadeamento de hash SHA-256 ($H_k = \text{SHA-256}(H_{k-1} \parallel \dots)$), algoritmo de detecção de adulteração (*tamper detection*) e emissão de recibos assinados pelo servidor resistentes a coerção.
- **Módulo 5 (`auditor.py`, `bin/audit_cli.py`):** Mecanismo de auditoria de confiança zero e CLI independente que valida continuidade da cadeia, assinaturas de todos os eleitores, unicidade de votos, recomputação homomórfica dos totais e consistência das fatias de decifração.

---

## 3. Guia Rápido de Instalação e Execução

O projeto conta com automação via `Makefile` para facilitar o fluxo de desenvolvimento:

```bash
# 1. Exibir ajuda de comandos disponíveis
make help

# 2. Instalar dependências principais e de desenvolvimento
make install

# 3. Inicializar o banco de dados SQLite local
make db-init

# 4. Executar os linters (Ruff e Pylint)
make lint

# 5. Formatar o código automaticamente (Ruff)
make format

# 6. Executar a suíte de testes com verificação de cobertura (mínimo 80%)
make test

# 7. Gerar relatório visual de cobertura em HTML (abrir em htmlcov/index.html)
make cov-html

# 8. Construir a documentação técnica (MkDocs)
make docs-build

# 9. Executar a simulação interativa da eleição (Demonstração Completa)
make run-demo

# 10. Executar a auditoria pública independente
make run-audit

# 11. Limpar caches, arquivos temporários e relatórios
make clean
```

---

## 4. Fluxo de Testes e Cobertura (>= 80%)

A integridade do código e a conformidade dos módulos são garantidas via `pytest` com a extensão `pytest-cov`:

```bash
pytest --cov=src/evoting --cov-report=term-missing --cov-fail-under=80
```

- A suíte de testes em `tests/` testa exaustivamente os modelos, serialização, banco de dados, fluxo de registro e CLI.
- Para cada função criptográfica que for implementada pelos integrantes, testes unitários dedicados baseados em TDD já estão estruturados em `tests/test_*.py` com instruções claras de asserções nos comentários `# TODO:`.

---

## 5. Regras de Linting e Qualidade de Código

Para garantir conformidade com a PEP 8 e prevenir vulnerabilidades, o repositório utiliza:
- **Ruff:** Linter e formatador de alta performance configurado em `pyproject.toml` (tamanho máximo de linha: 100 caracteres).
- **Pylint:** Análise estática profunda em `src/evoting`.
- **Pre-commit:** Ganchos automáticos de Git para verificar formatação, espaços em branco e arquivos YAML antes de cada commit.

```bash
# Executar verificação estática
make lint
```

---

## 6. Roteiro da Demonstração ao Vivo

O script `bin/election_cli.py` (ou `make run-demo`) orquestra o roteiro completo de demonstração da eleição em 8 etapas:

1. **Etapa 1 (Inicialização dos Parâmetros e Chave Conjunta):**
   - Apresentação do primo seguro RFC 3526 de 2048 bits ($p$) e gerador ($g = 2$).
   - Inicialização de 3 autoridades eleitorais e síntese da chave pública conjunta $h = \prod h_i \pmod p$.
2. **Etapa 2 (Registro dos Eleitores e Chaves RSA):**
   - Criação de identidades para `voter_001`, `voter_002` e `voter_003` com pares de chaves RSA-2048.
3. **Etapa 3 (Cifração de Votos e Emissão de Recibos):**
   - Eleitores cifram suas escolhas entre "Alice" e "Bob" usando Exponential ElGamal.
   - Cada cédula é assinada digitalmente e anexada ao quadro público de avisos.
   - O servidor emite um recibo digital assinado contendo o hash do bloco (sem vazar $r$).
4. **Etapa 4 (Demonstração: Rejeição de Voto Duplo):**
   - O eleitor `voter_001` tenta submeter uma segunda cédula.
   - O servidor detecta a tentativa de voto duplo e bloqueia sumariamente a inclusão no quadro.
5. **Etapa 5 (Demonstração: Detecção de Adulteração no Quadro Público):**
   - Simulação de um ataque por administrador malicioso que altera o valor da cifra $c_1$ do Bloco #1 no banco.
   - O algoritmo de verificação de integridade percorre a cadeia e **sinaliza a adulteração com sucesso** (`Chain integrity: False`).
   - O valor original é restaurado para a apuração.
6. **Etapa 6 (Totalização Homomórfica dos Votos):**
   - O servidor multiplica todas as cifras $c_{1, i}$ e $c_{2, i}$ no domínio cifrado.
   - Nenhuma cédula individual é decifrada.
7. **Etapa 7 (Demonstração: Falha de Apuração sem Todas as Autoridades):**
   - Tentativa de decifração da apuração utilizando apenas as fatias da Autoridade 1 e Autoridade 2.
   - A operação falha com `ValueError`, comprovando que o limiar conjunto de autoridades é inviolável.
8. **Etapa 8 (Decifração Final e Proclamação do Resultado):**
   - A Autoridade 3 fornece sua fatia de decifração.
   - Cancelamento homomórfico da máscara de aleatoriedade $h^R$ via inverso modular e recuperação dos totais via logaritmo discreto limitado:
     - **Alice:** 2 votos
     - **Bob:** 1 voto
   - Confirmação de todas as invariantes e provas criptográficas.

---

## 7. Quadro Kanban / Backlog de Tarefas (GitHub Projects)

A matriz de atribuições divide o trabalho de forma balanceada entre os 5 integrantes:

| Integrante | Módulo / Área | Tarefa Técnica (Issues do GitHub Projects) | Arquivos sob Custódia |
|---|---|---|---|
| **Integrante 1 (Dev A)** | **Módulo 1: Identidade & Assinaturas RSA** | - Implementar `generate_voter_rsa_keypair(key_size=2048)`.<br/>- Implementar `canonicalize_payload(payload)` determinístico.<br/>- Implementar `sign_ballot_payload` e `verify_ballot_signature` com RSA-PSS e SHA-256.<br/>- Implementar `check_voter_eligibility_and_unicity`.<br/>- Ativar e validar os testes unitários em `tests/test_rsa_signatures.py`. | `src/evoting/crypto/rsa.py`<br/>`src/evoting/voter.py`<br/>`tests/test_rsa_signatures.py` |
| **Integrante 2 (Dev B)** | **Módulo 2: Cifração Homomórfica de Cédulas** | - Implementar `sample_random_blinding_factor(p)` usando `secrets`.<br/>- Implementar `encrypt_vote(m, h, p, g)` com Exponential ElGamal e guardrail $m \in \{0, 1\}$.<br/>- Implementar `homomorphic_multiply_ciphertexts(ciphers, p)` garantindo redução modular.<br/>- Integrar cédulas multicandidato com `ballot.py`.<br/>- Ativar e validar os testes unitários em `tests/test_elgamal_encryption.py`. | `src/evoting/crypto/elgamal.py`<br/>`src/evoting/ballot.py`<br/>`tests/test_elgamal_encryption.py` |
| **Integrante 3 (Dev C)** | **Módulo 3: Autoridades e DKG** | - Implementar `generate_authority_keypair(p, g)` ($x_i, h_i = g^{x_i} \bmod p$).<br/>- Implementar `compute_joint_public_key(shares, p)` ($h = \prod h_i \bmod p$).<br/>- Implementar `compute_partial_decryption_share(tally, x_i, p)` ($D_i = C_1^{x_i} \bmod p$).<br/>- Implementar `combine_decryption_shares_and_recover` com inverso modular e log discreto.<br/>- Ativar e validar os testes em `tests/test_joint_decryption.py`. | `src/evoting/crypto/dkg.py`<br/>`src/evoting/authority.py`<br/>`tests/test_joint_decryption.py` |
| **Integrante 4 (Dev D)** | **Módulo 4: Quadro Público & Recibos** | - Implementar `compute_block_hash` com SHA-256 e concatenação canônica.<br/>- Implementar `verify_chain_integrity` para detecção de adulteração.<br/>- Implementar `issue_voter_receipt` assinado pelo servidor **omitindo $r$** (resistência à coerção).<br/>- Implementar `verify_receipt` com chave pública do servidor.<br/>- Ativar e validar os testes em `tests/test_bulletin_board.py`. | `src/evoting/bulletin_board.py`<br/>`src/evoting/receipt.py`<br/>`tests/test_bulletin_board.py` |
| **Integrante 5 (Dev E)** | **Módulo 5: Auditoria de Confiança Zero & CLI** | - Implementar `audit_hash_chain_integrity` e `audit_voter_signatures_and_unicity`.<br/>- Implementar `audit_homomorphic_tally_aggregation` e `audit_decryption_shares_and_results`.<br/>- Polir argumentos e saída da CLI em `bin/audit_cli.py`.<br/>- Ativar e validar os testes em `tests/test_audit_engine.py`. | `src/evoting/auditor.py`<br/>`bin/audit_cli.py`<br/>`tests/test_audit_engine.py` |

---

## 8. Licença e Autoria

Este projeto é desenvolvido para fins acadêmicos na disciplina de Segurança Computacional (2026). Consulte o arquivo `LICENSE` para termos de uso.
