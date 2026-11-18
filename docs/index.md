# Sistema de Votação Eletrônica Auditável e Segura

Bem-vindo à documentação técnica do **Sistema de Votação Eletrônica Auditável e Segura** (SegComp 2026).

Este projeto implementa uma infraestrutura completa de votação eletrônica de ponta a ponta verificável (*End-to-End Verifiable E-Voting*), combinando:

- **Identidade e Não-Repúdio:** Assinaturas digitais RSA-2048 com PSS e hashing SHA-256 (Módulo 1).
- **Sigilo do Voto e Homomorfismo Aditivo:** Cifração Exponencial ElGamal sobre o grupo primo seguro RFC 3526 MODP-2048 (Módulo 2).
- **Confiança Distribuída sem Ponto Único de Falha:** Geração de Chaves Distribuída (DKG) e Decifração por Limiar (*Threshold Decryption*) entre múltiplas autoridades (Módulo 3).
- **Quadro Público Imutável e Resistência à Coerção:** Livro-razão em cadeia de blocos (*append-only bulletin board*) com hashes SHA-256 e recibos assinados pelo servidor que omitem o fator de aleatoriedade $r$ (Módulo 4).
- **Auditoria de Confiança Zero:** Mecanismo de auditoria independente e CLI para verificação pública de integridade sem posse de chaves privadas (Módulo 5).

---

## Estrutura da Documentação

- [Arquitetura Criptográfica](architecture.md): Especificações matemáticas detalhadas, fórmulas de modularidade e divisão de módulos.
- [Modelo de Ameaças & Análise de Segurança](threat_model.md): Vetores de ataque, garantias de sigilo, integridade e resistência à coação.
- [Guia do Auditor Independente](audit_guide.md): Instruções passo a passo para auditores públicos recomputarem o resultado da eleição.

---

## Instalação Rápida

Consulte o [README.md](file:///home/gsperandio/Documentos/SegComp/projetoSegcomp/README.md) na raiz do projeto para o guia completo de comandos `make install`, `make test`, `make run-demo` e `make run-audit`.
