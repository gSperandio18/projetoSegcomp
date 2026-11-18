# Guia do Auditor Independente

O sistema disponibiliza a ferramenta `bin/audit_cli.py`, permitindo que qualquer cidadão, comitê ou entidade externa audite a eleição de forma 100% independente, utilizando exclusivamente os dados públicos do quadro de avisos (*bulletin board*).

---

## 1. Princípio da Confiança Zero (*Zero-Trust*)

O auditor independente não necessita de nenhuma chave privada nem de privilégios de administrador:
- Acessa apenas o banco de dados público SQLite (`election.db`) ou o arquivo exportado JSON do quadro de avisos.
- Utiliza apenas os parâmetros públicos da RFC 3526 MODP-2048 ($p, g$).
- Utiliza as chaves públicas RSA dos eleitores registrados e as fatias públicas de decifração $D_i$ das autoridades.

---

## 2. Como Executar a Auditoria

### Via Makefile:
```bash
make run-audit
```

### Via CLI com Parâmetros Customizados:
```bash
# Auditar a partir de um banco SQLite específico
python3 bin/audit_cli.py --db-path /caminho/para/eleicao.db

# Auditar a partir de um dump JSON exportado
python3 bin/audit_cli.py --board-json /caminho/para/board_dump.json --export-report relatorio.json
```

---

## 3. As 4 Etapas de Verificação

1. **Continuidade da Cadeia de Hash:**
   - Para cada bloco $k \in [1, N]$, calcula-se:
     $$H_k' = \text{SHA-256}(H_{k-1} \parallel k \parallel \text{voter\_id} \parallel \text{canonical}(cédula) \parallel \text{sig} \parallel \text{timestamp})$$
   - Confirma-se que $H_k' == H_k$.
2. **Autenticidade das Assinaturas e Unicidade:**
   - Verifica-se a assinatura RSA-PSS de cada bloco com a chave pública do eleitor correspondente.
   - Confirma-se que nenhum `voter_id` aparece mais de uma vez nos blocos.
3. **Recomputação do Produto Homomórfico:**
   - O auditor calcula publicamente:
     $$C_{1,\text{cand}} = \prod_{k=1}^N c_{1, k} \pmod p, \quad C_{2,\text{cand}} = \prod_{k=1}^N c_{2, k} \pmod p$$
4. **Verificação da Decifração e Totalização:**
   - Combina as fatias $D_i$:
     $$W = C_{2,\text{cand}} \cdot \left(\prod_{i=1}^K D_i\right)^{-1} \pmod p$$
   - Resolve o logaritmo discreto $g^M = W$ e compara o valor $M$ com o total anunciado oficialmente.
