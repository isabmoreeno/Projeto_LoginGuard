"""LoginGuard Streamlit SOC dashboard."""
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st

from loginguard.analysis import DetectionConfig, LogValidationError, detect_alerts, load_logs

ROOT = Path(__file__).parent
st.set_page_config(page_title="LoginGuard | SOC Monitor", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
.stApp {background:#0b1020;color:#e5eaf5} [data-testid="stSidebar"] {background:#11182a;border-right:1px solid #27334d}
[data-testid="stMetric"] {background:#131c30;border:1px solid #26334d;padding:16px;border-radius:12px}
[data-testid="stMetricValue"] {color:#f5f7ff} div[data-testid="stDataFrame"] {border:1px solid #26334d;border-radius:10px}
.lg-sub {color:#96a6c2} .lg-title {letter-spacing:.02em}
</style>
""", unsafe_allow_html=True)

st.sidebar.markdown("# 🛡️ LoginGuard")
st.sidebar.caption("AUTHENTICATION MONITOR · SOC N1")
page = st.sidebar.radio("Navegação", ["Dashboard", "Análise de logs", "Relatório de incidentes", "Sobre"], label_visibility="collapsed")
st.sidebar.divider()
st.sidebar.caption("Os alertas indicam atividade suspeita e requerem investigação. Não confirmam um ataque.")

with st.sidebar.expander("Regras de detecção", expanded=False):
    failures_threshold = st.number_input("Falhas para possível força bruta", min_value=2, max_value=100, value=5)
    window_minutes = st.number_input("Janela de força bruta (minutos)", min_value=1, max_value=1440, value=5)
    unique_users_threshold = st.number_input("Contas para possível spraying", min_value=2, max_value=100, value=5)
    spray_window_minutes = st.number_input("Janela de spraying (minutos)", min_value=1, max_value=1440, value=10)
    success_after_failures = st.number_input("Falhas antes de sinalizar sucesso", min_value=1, max_value=100, value=3)
config = DetectionConfig(int(window_minutes), int(failures_threshold), int(unique_users_threshold), int(success_after_failures), int(spray_window_minutes))

uploaded = st.sidebar.file_uploader("Carregar CSV de autenticação", type=["csv"], help="Máximo de 10 MB. Campos: timestamp, ip, username, status.")
if uploaded is not None:
    try:
        logs = load_logs(uploaded)
        st.session_state["logs"] = logs
        st.session_state["source_name"] = uploaded.name
    except LogValidationError as exc:
        st.sidebar.error(str(exc))
    except Exception as exc:
        st.sidebar.error(f"Falha ao processar arquivo: {exc}")
if "logs" not in st.session_state:
    try:
        st.session_state["logs"] = load_logs((ROOT / "data" / "demo_auth_logs.csv").read_bytes())
        st.session_state["source_name"] = "demo_auth_logs.csv (dados fictícios)"
    except Exception as exc:
        st.error(f"Não foi possível carregar os dados de demonstração: {exc}")
        st.stop()
logs = st.session_state["logs"]
alerts = detect_alerts(logs, config)

# Shared filters apply consistently to dashboard and report.
st.sidebar.markdown("### Filtros")
min_date, max_date = logs.timestamp.min().date(), logs.timestamp.max().date()
date_range = st.sidebar.date_input("Período (UTC)", value=(min_date, max_date), min_value=min_date, max_value=max_date)
ip_options = sorted(logs.ip.unique().tolist())
selected_ips = st.sidebar.multiselect("IP de origem", ip_options, placeholder="Todos os IPs")
severity_options = ["High", "Medium", "Low"]
selected_severities = st.sidebar.multiselect("Severidade", severity_options, default=severity_options)
if isinstance(date_range, tuple) and len(date_range) == 2:
    start = pd.Timestamp(date_range[0], tz="UTC")
    end = pd.Timestamp(date_range[1], tz="UTC") + pd.Timedelta(days=1) - pd.Timedelta(microseconds=1)
    filtered = logs[(logs.timestamp >= start) & (logs.timestamp <= end)]
else:
    filtered = logs
if selected_ips:
    filtered = filtered[filtered.ip.isin(selected_ips)]
filtered_alerts = detect_alerts(filtered, config)
filtered_alerts = filtered_alerts[filtered_alerts.severity.isin(selected_severities)] if not filtered_alerts.empty else filtered_alerts

def heading(title, subtitle):
    st.markdown(f"<h1 class='lg-title'>{title}</h1><p class='lg-sub'>{subtitle}</p>", unsafe_allow_html=True)

def alerts_table(frame):
    display = frame.copy()
    if not display.empty:
        display["timestamp"] = display.timestamp.dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    st.dataframe(display, use_container_width=True, hide_index=True,
                 column_config={"timestamp":"Horário (UTC)","ip":"IP de origem","severity":"Severidade","alert_type":"Tipo de alerta","attempts":"Tentativas","users":"Contas relacionadas","justification":"Justificativa"})

if page == "Dashboard":
    heading("Centro de monitoramento", "Visibilidade de autenticação e sinais que merecem investigação.")
    st.caption(f"Fonte ativa: **{st.session_state['source_name']}** · {len(filtered):,} eventos no filtro")
    successes = int((filtered.status == "success").sum()); failures = int((filtered.status == "failure").sum())
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Tentativas", f"{len(filtered):,}"); c2.metric("Bem-sucedidas", f"{successes:,}"); c3.metric("Malsucedidas", f"{failures:,}"); c4.metric("Alertas", f"{len(filtered_alerts):,}")
    left,right = st.columns(2)
    with left:
        st.subheader("Atividade por horário")
        if filtered.empty: st.info("Sem eventos para os filtros selecionados.")
        else:
            hourly = filtered.assign(hour=filtered.timestamp.dt.floor("h")).groupby(["hour","status"]).size().rename("Eventos").reset_index()
            fig=px.area(hourly,x="hour",y="Eventos",color="status",template="plotly_dark",color_discrete_map={"success":"#31c48d","failure":"#f97066"})
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",xaxis_title="Horário (UTC)",legend_title="Resultado")
            st.plotly_chart(fig,use_container_width=True)
    with right:
        st.subheader("IPs com mais falhas")
        top=filtered[filtered.status=="failure"].groupby("ip").size().nlargest(10).rename("Falhas").reset_index().sort_values("Falhas")
        if top.empty: st.info("Sem falhas no período selecionado.")
        else:
            fig=px.bar(top,x="Falhas",y="ip",orientation="h",template="plotly_dark",color="Falhas",color_continuous_scale="Reds")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",coloraxis_showscale=False,yaxis_title="IP")
            st.plotly_chart(fig,use_container_width=True)
    st.subheader("Histórico de alertas")
    alerts_table(filtered_alerts)
elif page == "Análise de logs":
    heading("Análise de logs", "Regras explicáveis para agrupar padrões de autenticação.")
    st.info("O arquivo é analisado em memória nesta sessão. Senhas não são aceitas nem armazenadas.")
    st.write(f"Eventos carregados: **{len(logs):,}** · Colunas normalizadas: timestamp, ip, username, status")
    if not logs.empty:
        st.write(f"Intervalo UTC: **{logs.timestamp.min():%Y-%m-%d %H:%M} — {logs.timestamp.max():%Y-%m-%d %H:%M}**")
    st.subheader("Alertas detectados")
    alerts_table(filtered_alerts)
elif page == "Relatório de incidentes":
    heading("Relatório de incidentes", "Resumo exportável de sinais suspeitos para triagem SOC.")
    st.caption("Cada alerta representa um indício para investigação, não uma confirmação de ataque.")
    alerts_table(filtered_alerts)
    if not filtered_alerts.empty:
        csv=filtered_alerts.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Baixar relatório CSV",csv,"loginguard_incident_report.csv","text/csv",use_container_width=False)
    else: st.info("Nenhum alerta corresponde aos filtros selecionados; não há relatório para exportar.")
elif page == "Sobre":
    heading("Sobre o LoginGuard", "Ferramenta didática de monitoramento de tentativas de autenticação.")
    st.markdown("""
**LoginGuard** demonstra uma rotina de triagem SOC N1 usando logs autorizados ou fictícios.

- Força bruta possível: falhas de um IP agrupadas numa janela configurável.
- Password spraying possível: falhas de um IP contra várias contas numa janela configurável.
- Sucesso após falhas: sucesso do mesmo IP precedido pelo limiar de falhas.
- Severidade **High** identifica padrões de volume; **Medium** destaca sucesso após falhas.

Todos os horários são tratados como UTC. Os dados enviados permanecem apenas na sessão e não são persistidos pelo aplicativo.
""")
