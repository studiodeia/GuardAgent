# F2 - Threat Intel Loader: Arquitetura e Implementação

Este documento detalha a arquitetura e a implementação do componente **Threat Intel Loader** do GuardAgent Gateway. Ele descreve as fontes de dados, pipeline ETL, esquema de banco de dados, deploy em Kubernetes e métricas de monitoramento.

## 1. Visão Geral
O objetivo do Threat Intel Loader é coletar indicadores de ameaça de múltiplas fontes públicas (NVD, Abuse.ch, MISP, OTX e feeds customizados) e disponibilizar essas informações para o mecanismo de detecção do GuardAgent. O sistema roda como um CronJob no Kubernetes e persiste os indicadores no PostgreSQL com cache em Redis.

## 2. Pipeline ETL
O fluxo principal segue a seguinte sequência:

1. **Extractor** – recupera dados de cada fonte respeitando limites de taxa.
2. **Transformer** – normaliza e enriquece os indicadores (IPs, domínios, URLs, hashes) gerando um `hash` único e informações adicionais como país ou ASN.
3. **Validator** – descarta registros com `confidence` abaixo do limiar configurado.
4. **Loader** – grava os indicadores validados no banco de dados e atualiza os índices de cache.

A implementação do pipeline encontra‑se em `internal/etl/pipeline.go` e usa um pool de workers para processar múltiplas fontes em paralelo.

## 3. Esquema de Banco de Dados
As tabelas principais são definidas em `migrations/001_create_threat_intel_tables.sql`.

- `threat_indicators`: armazena todos os indicadores normalizados, incluindo reputação e data de expiração.
- `threat_intel_sources`: controla o estado de cada feed e horário da última execução.
- `etl_jobs`: registra métricas de cada execução do loader.

## 4. Deploy Kubernetes
O arquivo `deploy/k8s/threat-intel-loader.yaml` define o CronJob responsável por executar o loader a cada quatro horas. As credenciais de acesso ao PostgreSQL, Redis e APIs externas são referenciadas via Secrets. O job utiliza requests mínimos de CPU e memória para evitar impacto no cluster.

## 5. Métricas e Observabilidade
O pacote `internal/metrics/threat_intel.go` exporta métricas Prometheus como:

- `threat_intel_etl_jobs_total{source,status}`
- `threat_intel_indicators_processed_total{source,type,action}`
- `threat_intel_query_duration_seconds{query_type}`

Essas métricas permitem acompanhar a saúde do pipeline e a qualidade dos feeds.

## 6. Interface de Consulta
O pacote `internal/threatintel/client.go` disponibiliza métodos para consultar rapidamente os indicadores armazenados, utilizando Redis para cache e um BloomFilter para evitar consultas desnecessárias ao banco.

## 7. Cronograma de Implementação
Conforme descrito em `roadmap/f2-threat-intel-loader.md`, a entrega está estimada em quatro semanas, dividida em:

1. Estrutura do ETL e migrations
2. Integração das fontes NVD e Abuse.ch
3. Implantação via Kubernetes com métricas
4. Testes de performance e documentação

---
