# VirusTotal rulesets exporter

Extract livehunt rulesets and rules from your VirusTotal account and write them to your local filesystem. The export can be done by making a filter on the name of your ruleset or the content of the rules inside them

## Installation
```
 go get github.com/codeyourweb/vt-rulesets-exporter
```

## Usage
```
vt-rulesets-exporter [-h|--help] -a|--apikey "<value>" [-o|--out
                            "<value>"] [-n|--ruleset-name "<value>"]
                            [-c|--rule-content "<value>"]
Arguments:

  -h  --help          Print help information
  -a  --apikey        VirusTotal API Key (only VT Entreprise key supported)
  -o  --out           Save *.yar files into the specified folder.
  -n  --ruleset-name  Filter string must match in ruleset(s) name
  -c  --rule-content  Filter string must match yara rules content
```

Filters could be string or regex. If so, your pattern have to be enclosed by / /
