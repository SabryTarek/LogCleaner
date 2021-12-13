# limitations
The first version supports only string and we handle them as byte array
You can see the example in the test.yar file
It simply uses like this: // $REPLACEMENT$ text goes here
Where text goes here used as a stiped byte array.

# create venv
py -m venv .\venv

# venv activate
.\venv\Scripts\activate

# install requirements
pip install -r requirements.txt

# example run
py .\cleans.py -y test.yar -f .\test_data\