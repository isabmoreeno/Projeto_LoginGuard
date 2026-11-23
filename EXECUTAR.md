# Executar LoginGuard no Windows

1. Instale Python 3.10 ou superior e marque **Add Python to PATH** no instalador.
2. Abra o PowerShell nesta pasta.
3. Crie e ative o ambiente virtual:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   Se a política bloquear a ativação, execute nesta janela `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` e ative novamente.

4. Instale dependências e inicie:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   streamlit run app.py
   ```

5. Abra o endereço local indicado pelo Streamlit (normalmente http://localhost:8501).
6. Para executar os testes: `python -m pytest -q`.

O dashboard inicia com `data/demo_auth_logs.csv`, cujos endereços IP reservados são exemplos fictícios. Envie CSV UTF-8 com colunas `timestamp,ip,username,status` (ou aliases documentados no README); timestamp precisa conter data/hora válida e status ser success/failure ou equivalente. Limite de upload: 10 MB.
