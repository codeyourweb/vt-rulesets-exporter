package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/VirusTotal/gyp"
	"github.com/antonholmquist/jason"
)

// VTBASEURL define the VirusTotal API endpoint for hash requesting
const VTBASEURL = "https://www.virustotal.com/api/v3/intelligence/hunting_rulesets"

// USERAGENT defines an existing UA instead of Golang one
const USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0"

// HTTPACCEPT defines what content type would be accepted
const HTTPACCEPT = "application/json,text/*;q=0.99"

// HTTPTIMEOUT defined the time exprimed in seconds for HTTP requests timeout
const HTTPTIMEOUT = 5

// DEFAULTSLEEPTIME is an integer value to generate time sleep in VirusTotal API receive a 429 HTTP code
const DEFAULTSLEEPTIME = 60

// APIERROR400 is the default error return message for HTTP 400 code
const APIERROR400 = "HTTP Bad request - Cannot proceed"

// APIERROR401 is the default error return message for HTTP 401 code
const APIERROR401 = "Wrong VirusTotal API key - Cannot proceed"

// APIERROR404 is the default error return message for HTTP 404 code
const APIERROR404 = "HTTP not found - Cannot proceed"

// APIERROR429 is the default error return message for HTTP 429 code
const APIERROR429 = "VirusTotal API request rate reached : sleeping some time..."

// VTRuleset wrap a complete VirusTotal ruleset content into a structure
type VTRuleset struct {
	Name  string
	Rules []VTRule
}

// VTRule wrap a go-gyp Rule into a more simple structure
type VTRule struct {
	Identifier string
	Content    []byte
}

// AddRules parse a string content for yara rules and add them in the Rules slice
func (f *VTRuleset) AddRules(data string) {
	reader := strings.NewReader(data)
	ruleset, err := gyp.Parse(reader)
	if err != nil {
		log.Println("Error parsing rules: ", err)
	} else {
		for _, rule := range ruleset.Rules {
			var r VTRule
			var buffer = new(bytes.Buffer)
			r.Identifier = rule.Identifier
			if err := rule.WriteSource(buffer); err != nil {
				log.Println("Error parsing rules: ", err)
			}
			r.Content = buffer.Bytes()
			f.Rules = append(f.Rules, r)
		}
	}
}

// FilterRules the portion of yara rules which match the specified string
func (f *VTRuleset) FilterRules(filter string) {

}

// HandleVirusTotalAPIQuery is a generic wrapper to handle VirusTotal API query
func HandleVirusTotalAPIQuery(VTurl string, VTkey string) (body []byte, err error) {
	var req *http.Request
	var res *http.Response

	if req, err = http.NewRequest("GET", VTurl, nil); err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", VTkey)
	req.Header.Set("User-Agent", USERAGENT)
	req.Header.Set("Accept", HTTPACCEPT)
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: time.Second * HTTPTIMEOUT}
	if res, err = client.Do(req); err != nil {
		return nil, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case 400:
		return nil, errors.New(APIERROR400)
	case 401:
		return nil, errors.New(APIERROR401)
	case 404:
		return nil, errors.New(APIERROR404)
	case 429:
		log.Println(APIERROR429)
		time.Sleep(DEFAULTSLEEPTIME * time.Second)
		return HandleVirusTotalAPIQuery(VTurl, VTkey)
	case 200:
		if body, err = ioutil.ReadAll(res.Body); err != nil {
			return nil, err
		}
		return body, nil
	default:
		return nil, errors.New("Unhandled API status code: " + fmt.Sprintf("%d", res.StatusCode))
	}
}

// RetriveVirusTotalRulesetsInformation get all of your ruleset and convert them into rulesets slices
func RetriveVirusTotalRulesetsInformation(VTkey string) (rulesets []VTRuleset, err error) {
	var body []byte
	var nextURL string

	if body, err = HandleVirusTotalAPIQuery(VTBASEURL, VTkey); err != nil {
		return rulesets, err
	}

	if rulesets, nextURL, err = ParseVirusTotalRulesetsJSON(body); err != nil {
		return rulesets, err
	}

	for len(nextURL) != 0 {
		if body, err = HandleVirusTotalAPIQuery(nextURL, VTkey); err != nil {
			return rulesets, err
		}

		var nextRulesets []VTRuleset
		if nextRulesets, nextURL, err = ParseVirusTotalRulesetsJSON(body); err != nil {
			return rulesets, err
		}
		for _, r := range nextRulesets {
			rulesets = append(rulesets, r)
		}

		rulesets = append(rulesets)
	}
	return rulesets, nil
}

// ParseVirusTotalRulesetsJSON handle raw json response from VTAPI
func ParseVirusTotalRulesetsJSON(res []byte) (rulesets []VTRuleset, nextURL string, err error) {
	var json *jason.Object

	json, err = jason.NewObjectFromBytes(res)
	if err != nil {
		return rulesets, nextURL, err
	}

	rulesetDetail, _ := json.GetObjectArray("data")
	for _, ruleset := range rulesetDetail {
		var rulesetObj VTRuleset
		rulesetObj.Name, _ = ruleset.GetString("attributes", "name")
		rules, _ := ruleset.GetString("attributes", "rules")
		rulesetObj.AddRules(rules)
		rulesets = append(rulesets, rulesetObj)
	}

	nextURL, _ = json.GetString("links", "next")

	return rulesets, nextURL, nil
}
