set -e

echo -ne 'Setup in progress...\n'
echo -ne 'Cleaning up previous builds...\n'
cd /tmp
rm -rf tevico-community

echo -ne 'Cloning the repository...\n'
git clone -b dev https://github.com/comprinnotech/tevico-community.git > /dev/null 2> /dev/null
cd tevico-community

echo -ne 'Setting up virtual environment...\n'
python3 -m venv .venv
source .venv/bin/activate

echo 'Installing dependencies...\n'

echo -ne '#####                     (33%)\r'
pip3 install poetry > /dev/null 2> /dev/null

echo -ne '#############             (66%)\r'
poetry install > /dev/null 2> /dev/null

echo -ne '#######################   (100%)\r'
echo -ne '\n'

echo -ne 'Running the application...\n'
/tmp/tevico-community/main run