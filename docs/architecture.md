# Arquitetura Criptográfica e Especificação dos Módulos

O sistema é construído sobre o grupo ciclíco de ordem prima $\mathbb{Z}_p^*$, padronizado pela **RFC 3526 (MODP Group 14)**, com primo seguro de 2048 bits $p$ e gerador $g = 2$, garantindo resistência a algoritmos de fatoração e cálculo de logaritmo discreto.

---

## 1. Mapeamento dos 5 Módulos

```
                                  +------------------------------------+
                                  |    Módulo 3: Autoridades & DKG     |
                                  |  h_i = g^(x_i) mod p; h = prod h_i |
                                  +-----------------+------------------+
                                                    |
                                                    v Chave Pública Conjunta h
+-------------------------------+       +-----------+--------------------+
|   Módulo 1: Eleitor & RSA     |       | Módulo 2: Cifração ElGamal     |
| Registra ID & Chave RSA-2048  | ----> | c1 = g^r mod p                 |
| Assina Cédula: Sig(H(Payload))|       | c2 = g^m * h^r mod p           |
+---------------+---------------+       +-----------+--------------------+
                |                                   |
                +-----------------+-----------------+
                                  |
                                  v Cédula Cifrada e Assinada
                        +---------+-------------------------+
                        | Módulo 4: Quadro Público & Recibo |
                        | H_k = SHA-256(H_{k-1} || Bloco_k) |
                        | Recibo Assinado (Sem r!)          |
                        +---------+-------------------------+
                                  |
                                  v Cadeia Pública de Blocos
                        +---------+-------------------------+
                        | Módulo 5: Auditoria Independente  |
                        | Validação de Hash-Chain & Assin.  |
                        | Recomputação Homomórfica C1 & C2  |
                        | Verificação de Fatias D_i & Tally |
                        +-----------------------------------+
```

---

## 2. Especificação Matemática por Módulo

### Módulo 1: Identidade e Assinaturas RSA (`crypto/rsa.py`, `voter.py`)
- **Geração de Chaves:** RSA-2048 com expoente público $e = 65537$.
- **Esquema de Assinatura:** RSA-PSS (*Probabilistic Signature Scheme*) com função de espalhamento SHA-256 e tamanho de sal máximo (`padding.PSS.MAX_LENGTH`).
- **Canonicalização:** Serialização determinística JSON com ordenação lexicográfica de chaves e delimitadores compactos:
  $$\text{Payload}_{\text{bytes}} = \text{canonicalize}(\text{payload})$$
- **Unicidade de Voto:** Cada eleitor autenticado possui um identificador único registrado no servidor eleitoral. A submissão de uma segunda cédula pelo mesmo eleitor é sumariamente rejeitada pelo controle de estado.

---

### Módulo 2: Cifração Homomórfica de Cédulas (`crypto/elgamal.py`, `ballot.py`)
- **Codificação de Voto:** Para cada candidato $j \in \{1, \dots, C\}$, o voto $m_j \in \{0, 1\}$.
  - $m_j = 1$: voto no candidato $j$.
  - $m_j = 0$: abstenção no candidato $j$.
- **Cifração Exponencial ElGamal:**
  Amostra-se $r \xleftarrow{R} [2, p - 2]$ via CSPRNG (`secrets`):
  $$c_1 = g^r \pmod p$$
  $$c_2 = g^m \cdot h^r \pmod p$$
- **Multiplicação Homomórfica:**
  Dadas $N$ cédulas cifradas $(c_{1, i}, c_{2, i})$ para um mesmo candidato:
  $$C_{1,\text{total}} = \prod_{i=1}^N c_{1, i} \pmod p = g^{\sum_{i=1}^N r_i} \pmod p$$
  $$C_{2,\text{total}} = \prod_{i=1}^N c_{2, i} \pmod p = g^{\sum_{i=1}^N m_i} \cdot h^{\sum_{i=1}^N r_i} \pmod p$$
  O produto homomórfico cifra exatamente o somatório de votos $M = \sum_{i=1}^N m_i$ sob a aleatoriedade acumulada $R = \sum_{i=1}^N r_i$.

---

### Módulo 3: DKG e Decifração Compartilhada (`crypto/dkg.py`, `authority.py`)
- **Geração Distribuída:** Cada autoridade $i \in \{1, \dots, K\}$ ($K \ge 3$) escolhe secretamente:
  $$x_i \xleftarrow{R} [2, p - 2], \quad h_i = g^{x_i} \pmod p$$
- **Chave Pública Conjunta:**
  $$h = \prod_{i=1}^K h_i \pmod p = g^{\sum_{i=1}^K x_i} \pmod p$$
- **Fatias de Decifração Parcial:**
  Dada a cifra agregada da apuração $(C_{1,\text{total}}, C_{2,\text{total}})$, cada autoridade calcula:
  $$D_i = (C_{1,\text{total}})^{x_i} \pmod p$$
- **Combinação e Cancelamento de Máscara:**
  $$D_{\text{total}} = \prod_{i=1}^K D_i \pmod p = (C_{1,\text{total}})^{\sum x_i} \equiv h^R \pmod p$$
  $$W = C_{2,\text{total}} \cdot (D_{\text{total}})^{-1} \pmod p \equiv g^M \pmod p$$
- **Recuperação por Logaritmo Discreto Limitado:**
  Como o número de votos $M \le N \le 10.000$, $M$ é recuperado eficientemente por busca limitada ou tabela de dispersão (*baby-step giant-step*).

---

### Módulo 4: Quadro Público e Recibos Verificáveis (`bulletin_board.py`, `receipt.py`)
- **Cadeia de Blocos Append-Only:**
  Para cada bloco $k \ge 1$:
  $$H_k = \text{SHA-256}(H_{k-1} \parallel k \parallel \text{voter\_id} \parallel \text{canonical}(cédula) \parallel \text{sig} \parallel \text{timestamp})$$
  O bloco 0 (Gênesis) possui $H_0$ apontando para a constante $0^{64}$.
- **Recibo do Eleitor:**
  $$\text{Recibo} = (\text{block\_index}, \text{block\_hash}, \text{voter\_id}, \text{Sign}_{SK_{\text{server}}}(H(\text{Recibo\_msg})))$$
  **Propriedade de Resistência à Coerção:** O recibo **NÃO CONTÉM** o fator de aleatoriedade $r$ nem o texto claro $m$, impossibilitando que um coator ou comprador de votos verifique a escolha do eleitor.

---

### Módulo 5: Auditoria Independente (`auditor.py`, `bin/audit_cli.py`)
- O auditor independente atua em modelo de **Confiança Zero**:
  1. Verifica a continuidade de toda a cadeia de hashes $H_0 \to H_1 \to \dots \to H_N$.
  2. Verifica a assinatura digital RSA de cada eleitor registrado e valida que nenhum eleitor votou mais de uma vez.
  3. Recomputa o produto homomórfico das cifras para todos os candidatos a partir dos blocos públicos.
  4. Verifica a combinação das fatias de decifração $D_i$ e confirma o resultado anunciado.
