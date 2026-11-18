# Modelo de Ameaças & Análise de Segurança

Este documento define o modelo de adversário, os vetores de ataque mitigados e as garantias criptográficas do sistema de votação eletrônica.

---

## 1. Capacidades do Adversário

Consideramos três classes principais de adversários:

1. **Adversário Externo / Intermediário de Rede (Man-in-the-Middle):**
   - Capacidade: Eavesdropping passivo no tráfego de rede, tentativa de injeção ou replay de cédulas antigas.
   - Mitigação: Cifração ElGamal com expoentes frescos via CSPRNG; assinaturas RSA-PSS determinísticas sobre payload canonicalizado; rejeição de replays por verificação de estado.
2. **Administrador de Banco de Dados Malicioso / Servidor Comprometido:**
   - Capacidade: Acesso direto de escrita ao banco de dados SQLite, tentativa de alterar votos registrados ou excluir cédulas de oponentes.
   - Mitigação: O encadeamento de hash SHA-256 torna qualquer alteração retroativa imediatamente detectável por qualquer observador ou pela CLI de auditoria independente (`bin/audit_cli.py`).
3. **Autoridade Eleitoral Conivente (Corrupção de até $K-1$ autoridades):**
   - Capacidade: Uma ou mais autoridades conspirando para tentar decifrar cédulas individuais antes da apuração.
   - Mitigação: A decifração exige **todas** as $K \ge 3$ fatias $D_i$. Nenhuma autoridade individual nem coalizão de tamanho $< K$ consegue isolar o texto claro. As autoridades só computam fatias sobre o produto homomórfico acumulado da eleição.

---

## 2. Invariantes de Segurança Fundamentais

| Invariante | Definição | Implementação / Mitigação |
|---|---|---|
| **Sigilo do Voto** | Nenhuma entidade descobre a escolha individual do eleitor. | Cifração ElGamal com chave pública conjunta $h = g^{\sum x_i} \pmod p$. |
| **Integridade de Cédula** | Votos não podem ser alterados após o envio. | Assinatura digital RSA-PSS pelo eleitor e hash SHA-256 no quadro público. |
| **Unicidade de Voto** | Exatamente 1 cédula computada por eleitor registrado. | Tabela de eleitores com flag `has_voted` e verificação de unicitade em tempo de inclusão. |
| **Detecção de Fraude de Cédula** | Um invasor não pode injetar votos múltiplos ($m > 1$). | Validação estrita $m \in \{0, 1\}$. |
| **Resistência à Coerção** | O eleitor não pode provar para terceiros em quem votou. | O recibo omitirá explicitamente a aleatoriedade $r$ do ElGamal. |
| **Auditabilidade Universal** | Qualquer cidadão pode verificar a apuração sem chaves privadas. | A CLI de auditoria recomputa os produtos homomórficos publicamente. |
