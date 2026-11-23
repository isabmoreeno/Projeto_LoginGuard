# LoginGuard

Dashboard didático de monitoramento e análise de tentativas de autenticação. O LoginGuard ajuda a praticar triagem SOC N1 ao destacar padrões suspeitos em logs autorizados ou fictícios. Um alerta é um indício para investigação; não confirma ataque.

## Objetivos

- Consolidar eventos de autenticação num painel simples.
- Aplicar regras transparentes e configuráveis para triagem.
- Explicar por que cada alerta foi gerado e exportar relatório CSV.
- Demonstrar práticas iniciais de validação e tratamento responsável de logs.

## Tecnologias

Python 3.10+, Streamlit, Pandas, Plotly e Pytest. Todas as dependências são gratuitas; não há APIs externas.

## Arquitetura

- `app.py`: interface, filtros, indicadores, visualizações, upload e exportação.
- `loginguard/analysis.py`: validação do CSV, normalização e mecanismos de detecção sem dependência da interface.
- `data/demo_auth_logs.csv`: conjunto pequeno, inteiramente fictício, com IPs reservados para documentação.
- `tests/test_analysis.py`: testes de validação e regras de deteção.

## Funcionalidades

- Indicadores de tentativas, sucessos, falhas e alertas.
- Série temporal de atividade e ranking de IPs por falhas.
- Upload CSV limitado a 10 MB; tipos, campos, timestamps, status e endereços IP validados.
- Alertas para falhas concentradas, falhas contra várias contas e sucesso após falhas.
- Filtros por período UTC, IP e severidade, aplicados ao painel e relatório.
- Justificativa, horário, IP, contas relacionadas e quantidade de eventos em cada alerta.
- Exportação CSV do relatório filtrado.

## Formato de entrada

Obrigatório: `timestamp`, `ip`, `username`, `status`. São aceitos aliases comuns: `time`/`datetime`/`date`/`horario`/`data_hora`; `source_ip`/`src_ip`/`ip_address`; `user`/`account`/`usuario`; `result`/`outcome`/`resultado`. Exemplos de status: `success`, `succeeded`, `ok`, `sucesso`; `failure`, `failed`, `fail`, `denied`, `falha`. Timestamps com fuso são recomendados; timestamps sem fuso são interpretados como UTC. Não inclua senhas, tokens ou segredos.

## Regras padrão

- **Possible brute force (High):** pelo menos 5 falhas do IP numa janela de 5 minutos.
- **Possible password spraying (High):** falhas do IP contra pelo menos 5 usernames distintos em até 10 minutos.
- **Success after repeated failures (Medium):** sucesso de um IP após pelo menos 3 falhas desse IP nos 5 minutos anteriores.

Todos os limiares e janelas podem ser configurados na barra lateral. O sistema agrega eventos; não conhece a política de bloqueio, a legitimidade do utilizador, NAT, proxies ou o contexto do ambiente. Severidade é triagem heurística.

## Instalação e execução

Consulte [EXECUTAR.md](EXECUTAR.md) para os comandos detalhados para Windows PowerShell. Resumo:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Para testar: `python -m pytest -q`.

## Exemplo de uso

1. Abra o menu **Análise de logs** e mantenha os dados fictícios ou carregue um CSV autorizado.
2. Ajuste os limiares em **Regras de detecção**.
3. Refine período, IP e severidade em **Filtros**.
4. Revise a justificativa na tabela e baixe o CSV em **Relatório de incidentes**.

## Exemplos de alertas

- Cinco falhas de `203.0.113.10` em aproximadamente três minutos: **Possible brute force**, High.
- Falhas de `198.51.100.24` contra cinco contas em quatro minutos: **Possible password spraying**, High.
- Sucesso de `203.0.113.10` logo após cinco falhas: **Success after repeated failures**, Medium.

Os exemplos são derivados dos eventos fictícios incluídos e são sinais para triagem, não conclusões sobre um atacante.

## Segurança e privacidade

Não recolhe credenciais e não executa tentativas de login. O arquivo é processado em memória na sessão Streamlit, sem persistência implementada. Em implantação remota, reveja autenticação da aplicação, retenção da sessão, transporte TLS, controles de acesso e política de dados antes de usar logs reais. Não envie dados que não esteja autorizado a analisar.

## Limitações conhecidas

- Regras heurísticas e simples, sem correlação com threat intelligence ou contexto de ativos.
- O agrupamento depende dos horários e IPs no CSV; NAT, proxies, relógios incorretos e eventos duplicados podem afetar resultados.
- CSV até 10 MB e sessão em memória; sem banco, auditoria, multiusuário ou ingestão contínua.
- Nenhuma classificação constitui confirmação de incidente.

## Melhorias futuras

Detecção de anomalias baseline, suporte a formatos de SIEM, deduplicação e qualidade de eventos, testes de interface, autenticação e RBAC, persistência opcional e alertas integrados a uma plataforma autorizada.

## Publicação no GitHub

Revise o CSV para garantir que contém apenas dados fictícios, confirme que `.env`, segredos e logs estão excluídos, adicione uma captura de tela demonstrativa, inclua licença apropriada e descreva explicitamente que é um projeto educacional com regras heurísticas. Configure GitHub Actions para executar `pytest` em cada alteração antes de publicar.
