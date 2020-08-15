pip3 install -U -r requirements.txt
sudo python3 -m spacy download en
chmod +x bin/*
sudo cp bin/* /usr/bin/
mkdir ~/.gf
cp templates/urlenum.json ~/.gf/urlenum.json
./run.sh