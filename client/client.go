//The client package provides convenience methods for authenticating with Bitpay and creating basic invoices.
package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	ku "github.com/themihai/bitpay-go/key_utils"
	log "github.com/golang/glog"
)

// The Client struct maintains the state of the current client. To use a client from session to session,
// the Pem and Token will need to be saved and used in the next client.
// The ClientId can be recreated by using the key_util.GenerateSinFromPem func, and the ApiUri
// will generally be https://bitpay.com.
// Insecure should generally be set to false or not set at all, there are a limited number of test
// scenarios in which it must be set to true.
type Client struct {
	Pem      string
	ApiUri   string
	Insecure bool
	ClientId string
	Token    Token
}

type Facade string

const (
	Public   Facade = "public"
	Pos      Facade = "pos"
	Merchant Facade = "merchant"
)

// @pem - received from New
func NewWithPem(pem string, facade Facade, test bool) (*Client, error) {
	cl := &Client{
		ApiUri: "https://bitpay.com",
		Pem:    pem,
	}
	if test {
		cl.ApiUri = "https://test.bitpay.com"
	}
	var err error
	cl.ClientId, err = ku.GenerateSinFromPem(cl.Pem)
	if err != nil {
		return nil, err
	}
	cl.Token.Token, err = cl.GetToken(string(facade))
	return cl, err
}

// Confirm the pairing code in https://bitpay.com/api-tokens
// Then use the pem to create new clients using NewWithPem
func New(label string, facade Facade, test bool) (pairingCode string, pem string, err error) {
	cl := &Client{
		Pem: ku.GeneratePem(),
	}
	if test {
		cl.ApiUri = "https://test.bitpay.com"
	}
	cl.ClientId, err = ku.GenerateSinFromPem(cl.Pem)
	if err != nil {
		return
	}
	code, err := cl.NewToken(label, facade)
	if err != nil {
		return "", "", err
	}
	return code, cl.Pem, nil
}

func (cl *Client) NewToken(label string, facade Facade) (pairingCode string, err error) {
	URL := cl.ApiUri + "/tokens"
	v := url.Values{}
	v.Add("label", label)
	v.Add("facade", string(facade))
	v.Add("id", cl.ClientId)

	hcl := http.DefaultClient
	bodyStr := v.Encode()
	req, err := http.NewRequest("POST", URL, strings.NewReader(bodyStr))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(bodyStr)))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-accept-version", "2.0.0")
	rsp, err := hcl.Do(req)
	if err != nil {
		return "", err
	}
	tk, err := decodeToken(rsp)
	if err != nil {
		log.Errorf("URL %s, v %s", URL, v.Encode())
		return "", err
	}
	return tk.PairingCode, nil
}

// The Token struct is a go mapping of a subset of the JSON returned from the server
// with a request to authenticate (pair).
type Token struct {
	Token             string
	Facade            string
	DateCreated       float64
	PairingExpiration float64
	Resource          string
	PairingCode       string
}

// Go struct mapping the JSON returned from the BitPay server when sending a POST or GET request to /invoices.

type Invoice struct {
	OrderId         string
	Url             string
	Status          string
	BtcPrice        string
	BtcDue          string
	Price           float64
	Currency        string
	ExRates         map[string]float64
	InvoiceTime     int64
	ExpirationTime  int64
	CurrentTime     int64
	Guid            string
	Id              string
	BtcPaid         string
	Rate            float64
	ExceptionStatus bool
	PaymentUrls     map[string]string
	Token           string
}

type TransactionSpeed string

const (
	// An invoice is considered to be confirmed immediately upon receipt of payment.
	High TransactionSpeed = "high"
	// An invoice is considered to be confirmed after 1 block confirmation (~10 minutes).
	Medium TransactionSpeed = "medium"
	// An invoice is considered to be confirmed after 6 block confirmations (~1 hour).
	Low TransactionSpeed = "low"
)

type IPNOpt struct {
	// passthru variable provided by the merchant and designed to be used
	// by the merchant to correlate the invoice with an order or other object
	// in their system. Maximum string length is 100 characters.
	// This passthru variable can be a JSON-encoded string, e.g.:
	// posData: '{ "ref" : 711454, "affiliate" : "spring112" }'
	PosData string
	// A URL to send status update messages to your server
	// This must be an https URL
	// BitPay will send an IPN callback to this URL when the invoice status changes.
	NotificationURL string
	// If not set on the invoice, transactionSpeed will
	// default to your account-level Order Settings.
	//  Note: orders are always posted to your BitPay Account Summary
	// for settlement after 6 block confirmations (regardless of this setting).
	TransactionSpeed TransactionSpeed
	// If true Notifications will be sent on every status change else
	// Notifications are only sent when an invoice is confirmed (according to the transactionSpeed setting).
	FullNotifications bool
	NotificationEmail *mail.Address
}

type OrderOpt struct {
	// This is the URL for a return link that is displayed on the receipt,
	// to return the shopper back to your website after a successful purchase.
	// This could be a page specific to the order, or to their account.
	RedirectURL string
	// Can be used by the merchant to assign their own internal ID to an invoice.
	// If used, there should be a direct match between an orderId and an invoiceId.
	OrderId string
	// Used to display an item description to the buyer. Maximum string length is 100 characters.
	ItemDesc string
	// Used to display an item SKU code or part number to the buyer. Maximum string length is 100 characters.
	ItemCode string
	// Indicates a physical item will be shipped (or picked up).
	Physical bool
	// Buyer Fields
	// These fields are used for display purposes only and will be shown on the invoice
	// if provided. Maximum string length of each field is 100 characters.
	BuyerName     string
	BuyerAddress1 string
	BuyerAddress2 string
	BuyerCity     string
	BuyerState    string
	BuyerZip      string
	BuyerCountry  string
	BuyerEmail    string
	BuyerPhone    string
}

// CreateInvoice returns an invoice type or pass the error from the server.
// The method will create an invoice on the BitPay server.
// @ipn and @order are optional
func (client *Client) CreateInvoice(price float64, currency string, ipn *IPNOpt, order *OrderOpt) (*Invoice, error) {
	if client.Token.Token == "" {
		return nil, fmt.Errorf("Invalid/empty token")
	}
	match, _ := regexp.MatchString("^[[:upper:]]{3}$", currency)
	if !match {
		return nil, errors.New("BitPayArgumentError: invalid currency code")
	}
	paylo := make(map[string]string)
	var floatPrec int
	if currency == "BTC" {
		floatPrec = 8
	} else {
		floatPrec = 2
	}
	priceString := strconv.FormatFloat(price, 'f', floatPrec, 64)
	paylo["price"] = priceString
	paylo["currency"] = currency
	paylo["token"] = client.Token.Token
	paylo["id"] = client.ClientId
	if ipn != nil {
		paylo["posData"] = ipn.PosData
		paylo["notificationURL"] = ipn.NotificationURL
		paylo["transactionSpeed"] = string(ipn.TransactionSpeed)
		if ipn.FullNotifications {
			paylo["fullNotifications"] = "true"
		}
		if ipn.NotificationEmail != nil {
			paylo["notificationEmail"] = ipn.NotificationEmail.String()
		}
	}
	if order != nil {
		paylo["redirectURL"] = order.RedirectURL
		paylo["orderId"] = order.OrderId
		paylo["itemDesc"] = order.ItemDesc
		paylo["itemCode"] = order.ItemCode
		if order.Physical {
			paylo["physical"] = "true"
		}
		paylo["buyerName"] = order.BuyerName
		paylo["buyerAddress1"] = order.BuyerAddress1
		paylo["buyerAddress2"] = order.BuyerAddress2
		paylo["buyerCity"] = order.BuyerCity
		paylo["buyerState"] = order.BuyerState
		paylo["buyerZip"] = order.BuyerZip
		paylo["buyerCountry"] = order.BuyerCountry
		paylo["buyerEmail"] = order.BuyerEmail
		paylo["buyerPhone"] = order.BuyerPhone

	}
	response, err := client.Post("invoices", paylo)
	if err != nil {
		return nil, err
	}
	return processInvoice(response)
}

// PairWithFacade
func (client *Client) PairWithFacade(str string) (*Token, error) {
	paylo := make(map[string]string)
	paylo["facade"] = str
	return client.PairClient(paylo)
}

// PairWithCode retrieves a token from the server and authenticates the keys of the calling client.
// The string passed to the client is a "pairing code" that must be retrieved
// from https://bitpay.com/dashboard/merchant/api-tokens.
// PairWithCode returns a Token type that must be assigned to the Token field of a client in order
// for that client to create invoices. For example `client.Token = client.PairWithCode("abcdefg")`.
func (client *Client) PairWithCode(str string) (*Token, error) {
	match, _ := regexp.MatchString("^[[:alnum:]]{7}$", str)
	if !match {
		return nil, errors.New("BitPayArgumentError: invalid pairing code")
	}
	paylo := make(map[string]string)
	paylo["pairingCode"] = str
	return client.PairClient(paylo)
}

func (client *Client) PairClient(paylo map[string]string) (*Token, error) {
	var err error
	client.ClientId, err = ku.GenerateSinFromPem(client.Pem)
	if err != nil {
		return nil, err
	}
	paylo["id"] = client.ClientId

	url := client.ApiUri + "/tokens"
	htclient := setHttpClient(client)
	payload, err := json.Marshal(paylo)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	req.Header.Add("content-type", "application/json")
	req.Header.Add("accept", "application/json")
	req.Header.Add("X-accept-version", "2.0.0")
	response, err := htclient.Do(req)
	if err != nil {
		return nil, err
	}
	return decodeToken(response)
}

func decodeToken(response *http.Response) (*Token, error) {
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var jsonContents map[string]interface{}
	if err = json.Unmarshal(contents, &jsonContents); err != nil {
		return nil, err
	}
	if response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("Error %s", contents)
		return nil, processErrorMessage(response, jsonContents)
	}
	return processToken(response, jsonContents)
}

func (client *Client) Post(path string, paylo map[string]string) (*http.Response, error) {
	url := client.ApiUri + "/" + path
	htclient := setHttpClient(client)
	payload, err := json.Marshal(paylo)
	if err != nil {
		return nil, err
	}
	log.Errorf("POST %s \n Data: %s", url, payload)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/json")
	req.Header.Add("accept", "application/json")
	req.Header.Add("X-accept-version", "2.0.0")
	publ, err := ku.ExtractCompressedPublicKey(client.Pem)
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Identity", publ)
	sig, err := ku.Sign(url+string(payload), client.Pem)
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Signature", sig)
	return htclient.Do(req)
}

// GetInvoice is a public facade method, any client which has the ApiUri field set can retrieve an invoice
// from that endpoint, provided they have the invoice id.
func (client *Client) GetInvoice(invId string) (*Invoice, error) {
	url := client.ApiUri + "/invoices/" + invId
	htclient := setHttpClient(client)
	response, err := htclient.Get(url)
	if err != nil {
		return nil, err
	}
	return processInvoice(response)
}

func (client *Client) GetTokens() (tokes []map[string]string, err error) {
	url := client.ApiUri + "/tokens"
	htclient := setHttpClient(client)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/json")
	req.Header.Add("accept", "application/json")
	req.Header.Add("X-accept-version", "2.0.0")
	publ, err := ku.ExtractCompressedPublicKey(client.Pem)
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Identity", publ)
	sig, err := ku.Sign(url, client.Pem)
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Signature", sig)
	response, err := htclient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var jsonContents map[string]interface{}
	if err = json.Unmarshal(contents, &jsonContents); err != nil {
		return nil, err
	}
	if response.StatusCode/100 != 2 {
		return nil, processErrorMessage(response, jsonContents)
	}
	this, err := json.Marshal(jsonContents["data"])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(this, &tokes)
	return tokes, err
}

func (client *Client) GetToken(facade string) (token string, err error) {
	tokens, err := client.GetTokens()
	if err != nil {
		return "", err
	}
	for _, token := range tokens {
		toke, ok := token[facade]
		if ok {
			return toke, nil
		}
	}
	return "error", errors.New("facade not available in tokens")
}

func setHttpClient(client *Client) *http.Client {
	var trans http.RoundTripper
	if client.Insecure {
		trans = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		trans = &http.Transport{}
	}
	//if client.legacyKey == "" {
	return &http.Client{Transport: trans}
	//}
	//authTrans := &basicAuthTransport{transport: trans, token: client.legacyKey}
	//return &http.Client{Transport: authTrans}
}

// basicAuthTransport is an http.RoundTripper that authenticates all requests
// using HTTP Basic Authentication using the provided token.
type basicAuthTransport struct {
	// API Token
	token string
	// Transport is the underlying HTTP transport to use when making requests.
	transport http.RoundTripper
}

// RoundTrip implements the RoundTripper interface.
// https://bitpay.com/downloads/bitpayApi-0.3.pdf -> Activating API Access
func (t *basicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request
	rClone := new(http.Request)
	*rClone = *req
	rClone.Header = make(http.Header, len(req.Header))
	for idx, header := range req.Header {
		rClone.Header[idx] = append([]string(nil), header...)
	}
	rClone.SetBasicAuth(t.token, "")
	return t.transport.RoundTrip(rClone)
}

func processErrorMessage(response *http.Response, jsonContents map[string]interface{}) error {
	responseStatus := strconv.Itoa(response.StatusCode)
	contentError := responseStatus + ": " + jsonContents["error"].(string)
	return errors.New(contentError)
}

func processToken(response *http.Response, jsonContents map[string]interface{}) (*Token, error) {
	datarray := jsonContents["data"].([]interface{})
	data, err := json.Marshal(datarray[0])
	if err != nil {
		return nil, err
	}
	tok := new(Token)
	err = json.Unmarshal(data, tok)
	return tok, err
}

func processInvoice(response *http.Response) (*Invoice, error) {
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var jsonContents map[string]interface{}
	if err := json.Unmarshal(contents, &jsonContents); err != nil {
		return nil, err
	}
	if response.StatusCode/100 != 2 {
		return nil, processErrorMessage(response, jsonContents)
	}
	this, err := json.Marshal(jsonContents["data"])
	if err != nil {
		return nil, err
	}
	inv := new(Invoice)
	err = json.Unmarshal(this, inv)
	return inv, err
}
