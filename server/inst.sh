deactivate || true
rm -rf lenv
python3 -m venv lenv
source lenv/bin/activate
pip install -r requirements.txt
