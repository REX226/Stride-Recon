1.tools used:-
Subfinder
assetfinder
gau
dnsx
httpx
naabu
katana
nuclei
arjun
subjack




2.Clone the Repository:-
git clone https://github.com/REX226/Stride-Recon.git
cd Stride-Recon


3.pip install -r requirements.txt

4.Install the 10-Tool Go Suite
to install the tools into their go/bin folder.run this single command:

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest github.com/projectdiscovery/httpx/cmd/httpx@latest github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest github.com/projectdiscovery/katana/cmd/katana@latest github.com/projectdiscovery/dnsx/cmd/dnsx@latest github.com/projectdiscovery/naabu/v2/cmd/naabu@latest github.com/lc/gau/v2/cmd/gau@latest github.com/tomnomnom/assetfinder@latest github.com/haccer/subjack@latest

Note: Arjun is installed via pip (included in requirements.txt).

5.Environment Path (CRITICAL)
 must ensure their Go binary folder is in their System PATH so Python can "find" the tools.

Windows: C:\Users\<Username>\go\bin

6.python app.py (to run the app)

