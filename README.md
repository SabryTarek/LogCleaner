# limitations
The first version supports only string and we handle them as byte array
You can see the example in the test.yar file
It simply uses like this: // $REPLACEMENT$ text goes here
Where text goes here used as a stiped byte array.

# create venv
python -m venv .\venv

# venv activate
.\venv\Scripts\activate

# install requirements
pip install -r requirements.txt

# example run
python cleans.py -y test.yar -f test_data -o out

# Project Structure

├── cleans.py
├── README.md
├── requirements.txt
├── test_data
│   ├── New folder
│   │   ├── SubFodler
│   │   │   └── test3.txt
│   │   └── test2.txt
│   └── test.txt
└── test.yar

3 directories, 7 files
