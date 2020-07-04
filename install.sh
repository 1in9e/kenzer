pip3 install -U -r requirements.txt
sudo python3 -m spacy download en
chmod +x bin/*
sudo cp bin/* /usr/bin/
bash run.sh