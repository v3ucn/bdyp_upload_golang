package bdyp

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"strings"
)

func debugJSON(v interface{}) string {
	bs, err := json.Marshal(v)
	if err != nil {
		return "<INVALID JSON>"
	} else {
		return string(bs)
	}
}

func (r *Bcloud) requestForm(method, uri string, req interface{}, resp interface{}) error {
	return r.request("form", method, uri, req, resp)
}

func toFiles(body map[string]interface{}) (io.Reader, int64, string, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	var length int64
	for key, r := range body {
		switch r := r.(type) {
		case io.Reader:
			fw, err := w.CreateFormFile(key, "filename")
			if err != nil {
				return nil, 0, "", err
			}
			length, err = io.Copy(fw, r)
			if err != nil {
				return nil, 0, "", err
			}
		case string:
			w.WriteField(key, r)
		}
	}
	w.Close()

	return &b, length, w.FormDataContentType(), nil
}

func (r *Bcloud) request(requestType string, method, uri string, req interface{}, resp interface{}) error {
	reqString := debugJSON(req)
	if len(reqString) < 1024 {
		fmt.Printf("[xyun] %s#%s start\n", method, uri)
	} else {
		fmt.Printf("[xyun] %s#%s start, req=<too-long>\n", method, uri)
	}

	query, headers, body, err := parseBody(requestType, req)
	if err != nil {
		return err
	}

	if len(query) > 0 {
		uriParsed, err := url.Parse(uri)
		if err != nil {
			return err
		}

		uriParsed.RawQuery = query.Encode()
		uri = uriParsed.String()
	}

	request, err := http.NewRequest(method, uri, body)
	if err != nil {
		return err
	}
	for k, v := range headers {
		request.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if resp != nil {
		bs, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		fmt.Printf("[xyun] %s#%s resp: %s\n", method, uri, bs)
		err = json.Unmarshal(bs, resp)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Bcloud) requestJSON(method, uri string, req interface{}, resp interface{}) error {
	return r.request("json", method, uri, req, resp)
}

func parseBody(requestType string, v interface{}) (url.Values, map[string]string, io.Reader, error) {
	query := url.Values{}
	body := map[string]string{}
	files := map[string]interface{}{}
	headers := map[string]string{}
	var body2 io.Reader

	if v == nil {
		return query, headers, body2, nil
	}

	vv := reflect.ValueOf(v)
	if vv.Kind() == reflect.Ptr {
		vv = vv.Elem()
	}
	if vv.Kind() != reflect.Struct {
		return nil, nil, nil, fmt.Errorf("%v is not a struct", v)
	}

	t := vv.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fieldV := vv.Field(i)
		if !fieldV.IsValid() {
			continue
		}
		if fieldV.Kind() == reflect.Ptr && fieldV.IsNil() {
			continue
		}
		if fieldV.Kind() == reflect.Slice && fieldV.Len() == 0 {
			continue
		}

		if key := f.Tag.Get("query"); key != "" {
			query.Add(key, reflectValueToString(vv.Field(i)))
		} else if key := f.Tag.Get("json"); key != "" {
			if strings.HasSuffix(key, ",omitempty") {
				key = key[:len(key)-len(",omitempty")]
			}
			body[key] = reflectValueToString(vv.Field(i))
		} else if key := f.Tag.Get("file"); key != "" {
			files[key] = vv.Field(i).Interface().(io.Reader)
		} else {
			return nil, nil, nil, fmt.Errorf("%v is not support", v)
		}
	}

	if len(body) > 0 || len(files) > 0 {
		if requestType == "url-encode" {
			values := url.Values{}
			for k, v := range body {
				values.Add(k, v)
			}
			body2 = strings.NewReader(values.Encode())
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		} else if requestType == "form" {
			tmp, length, contentType, err := toFiles(files)
			if err != nil {
				return nil, nil, nil, err
			}
			body2 = tmp
			headers["Content-Type"] = contentType
			headers["Content-Length"] = fmt.Sprintf("%d", length)
		} else {
			bs, _ := json.Marshal(body)
			body2 = strings.NewReader(string(bs))
			headers["Content-Type"] = "application/json"
		}
	}

	return query, headers, body2, nil
}

func reflectValueToString(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%d", v.Uint())
	case reflect.Float32, reflect.Float64:
		return fmt.Sprintf("%f", v.Float())
	case reflect.Bool:
		return fmt.Sprintf("%t", v.Bool())
	case reflect.Slice:
		return fmt.Sprintf("%v", v.Interface())
	case reflect.Map:
		return fmt.Sprintf("%v", v.Interface())
	case reflect.Struct:
		return fmt.Sprintf("%v", v.Interface())
	case reflect.Ptr:
		return reflectValueToString(v.Elem())
	default:
		return fmt.Sprintf("%v", v.Interface())
	}
}

func getMd5(bs []byte) string {
	res := md5.Sum(bs)
	return fmt.Sprintf("%x", res)
}

func ptrInt64(v int64) *int64 {
	return &v
}

func (r *Bcloud) requestURLEncode(method, uri string, req interface{}, resp interface{}) error {
	return r.request("url-encode", method, uri, req, resp)
}

func (r *Bcloud) getAuthToken() (string, error) {
	if err := r.refreshAuthToken(); err != nil {
		return "", err
	}
	return r.accessToken, nil
}

func (r *Bcloud) refreshAuthToken() error {
	if r.accessToken != "" {
		return nil
	}
	res, err := r.AuthRefreshToken(r.refreshToken)
	if err != nil {
		return err
	}
	r.accessToken = res.AccessToken
	return nil
}

func (r *Bcloud) AuthRefreshToken(refreshToken string) (*Token, error) {
	url := fmt.Sprintf("https://openapi.baidu.com/oauth/2.0/token?"+
		"grant_type=refresh_token&"+
		"refresh_token=%s&"+
		"client_id=%s&"+
		"client_secret=%s", refreshToken, r.app_key, r.app_secret)
	resp := new(tokenResp)
	err := r.requestJSON(http.MethodGet, url, nil, resp)
	if err != nil {
		return nil, err
	} else if resp.ErrorDescription != "" {
		return nil, fmt.Errorf(resp.ErrorDescription)
	}

	r.accessToken = resp.AccessToken
	r.refreshToken = resp.RefreshToken

	return resp.Token, nil
}
