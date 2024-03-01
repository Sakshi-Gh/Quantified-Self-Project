To run the Qunatified Self application, following libraries are required:
Flask
flask_sqlalchemy
flask_wtforms
flask_migrate
matplotlib
datetime

Required command to install the virtual environment (VsCode Windows)-
virtualenv env

Required command to activate the virtual environment (Windows)-
.\env\Scripts\activate.bat

Required commands to install the libraries-
pip install flask
pip install flask_sqlalchemy
pip install flask_wtforms
pip install flask_migrate
pip install matplotlib

Once the requiremnets are satisfied, the python file can be run on an editor like VsCode.
Alternatively, from command terminal the following command can also be used-
python app.py

The database file database.db needs to be in the same directory as the app.py file, along with the templates and static folders.
After running the app.py file, the URL 127.0.0.1:5000 (5000 is the default Flask Port) needs to be opened.
The application will start running.