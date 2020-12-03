package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/akamensky/argparse"
)

func main() {

	parser := argparse.NewParser("vt-rulesets-exporter", "Extract VirusTotal livehunt rulesets and rules to local filesystem")
	pApikey := parser.String("a", "apikey", &argparse.Options{Required: true, Help: "VirusTotal API Key (only VT Entreprise key supported)"})
	pOutPath := parser.String("o", "out", &argparse.Options{Required: false, Default: "", Help: "Save *.yar files into the specified folder"})
	pFilterRulesetName := parser.String("n", "ruleset-name", &argparse.Options{Required: false, Help: "Filter string must match in ruleset(s) name"})
	pFilterRuleContent := parser.String("c", "rule-content", &argparse.Options{Required: false, Help: "Filter string must match yara rules content"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	outPath := *pOutPath
	if len(outPath) == 0 {
		outPath = "./"
	}

	if rulesets, err := RetriveVirusTotalRulesetsInformation(*pApikey); err != nil {
		log.Fatal(err)
	} else {
		for _, ruleset := range rulesets {
			if len(*pFilterRulesetName) > 0 && !matchPattern(ruleset.Name, *pFilterRulesetName) {
				continue
			}

			for _, rule := range ruleset.Rules {
				if len(*pFilterRuleContent) > 0 && !matchPattern(string(rule.Content), *pFilterRuleContent) {
					continue
				}

				if err := writeRulesToLocalFilesystem(outPath+"/"+ruleset.Name, rule); err != nil {
					log.Println(err)
				}
			}

		}
	}
}

func matchPattern(value string, pattern string) bool {
	if len(pattern) > 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/' {
		r, err := regexp.Compile(pattern[1 : len(pattern)-1])
		if err != nil {
			log.Fatal(err)
		}
		return r.MatchString(value)
	}
	return strings.Contains(value, pattern)
}

func writeRulesToLocalFilesystem(rulePath string, rule VTRule) (err error) {
	_, err = os.Stat(rulePath)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(rulePath, 0600); err != nil {
			return err
		}
	}

	if err := ioutil.WriteFile(rulePath+"/"+rule.Identifier+".yar", rule.Content, 0644); err != nil {
		log.Println("Cannot write", rule.Identifier)
	}

	return nil
}
