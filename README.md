#SKS Explorer

**NOTE: THIS PROJECT IS NOT COMPLETE YET**

Demo: https://research.daylightpirates.org/sks-explorer

This is a project that allows you explore the SKS keyserver pool
via web interface.

###How to setup this app and run it locally

```sh
# 1. Install git, PostgreSQL, python, and virtualenv.
sudo apt-get install git postgresql pos python python-virtualenv

# 2. Clone this repo.
git clone https://github.com/diafygi/sks-explorer.git
cd sks-explorer

# 3. Create a virtualenv
virtualenv venv

# 4. Install the python requirements
venv/bin/pip install -r requirements.txt

# 5. Setup the database.
sudo -u postgres psql -c "CREATE DATABASE sks_explorer_db;"
sudo -u postgres psql -c "CREATE USER sks_explorer_user WITH PASSWORD '<sks_explorer_pass>';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sks_explorer_db TO sks_explorer_user;"
export SQLALCHEMY_DATABASE_URI="postgresql://sks_explorer_user:<sks_explorer_pass>@localhost/sks_explorer_db"

# 6. Download and import the latest sql dump.
venv/bin/python -c "import src.models; src.models.db.drop_all();"
wget https://research.daylightpirates.org/sks-dumps/latest/sql/sks-dump.postgresql -O /tmp/sks-dump.postgresql
sudo -u postgres psql sks_explorer_db < /tmp/sks-dump.postgresql

# 6 (alt). Alternatively, download the json dump and use the loader script.
venv/bin/python -c "import src.models; src.models.db.drop_all();"
venv/bin/python -c "import src.models; src.models.db.create_all();"
wget -r -np -nH --cut-dirs=3 -R index.html -P /tmp/sks-json/ https://research.daylightpirates.org/sks-dumps/latest/json/
venv/bin/python src/loader.py "/tmp/sks-json/*.json.gz"

# 7. Start up the website!
venv/bin/python src/views.py

# Open your browser to http://localhost:5000/
```

