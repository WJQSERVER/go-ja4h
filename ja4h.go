package ja4h

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// 将HTTP方法转换为小写并取前两个字符
func http_method(method string) string {
	return strings.ToLower(method)[:2]
}

// 处理HTTP版本，返回相应的简化版本
func http_version(version string) string {
	v := strings.Split(version, "/")
	if len(v) == 2 {
		if v[1] == "2" || v[1] == "2.0" {
			return "20"
		}
	}
	return "11"
}

// 检查请求中是否包含Cookie
func hasCookie(req *http.Request) string {
	if len(req.Cookies()) > 0 {
		return "c"
	}
	return "n"
}

// 检查请求中是否包含Referer
func hasReferer(referer string) string {
	if referer != "" {
		return "r"
	}
	return "n"
}

// 计算HTTP头的数量（忽略Cookie和Referer）
func num_headers(headers http.Header) int {
	len_headers := len(headers)
	if headers.Get("Cookie") != "" {
		len_headers--
	}
	if headers.Get("Referer") != "" {
		len_headers--
	}
	return len_headers
}

// 获取Accept-Language头的语言信息
func language(headers http.Header) string {
	lan := headers.Get("Accept-Language")
	if lan != "" {
		clean := strings.ReplaceAll(lan, "-", "")
		lower := strings.ToLower(clean)
		first := strings.Split(lower, ",")[0] + "0000"
		return first[:4]
	}
	return "0000"
}

// 生成JA4H_a部分
func JA4H_a(req *http.Request) string {
	method := http_method(req.Method)
	version := http_version(req.Proto)
	cookie := hasCookie(req)
	referer := hasReferer(req.Referer())
	num_headers := num_headers(req.Header)
	accept_lang := language(req.Header)

	return fmt.Sprintf("%s%s%s%s%02d%s", method, version, cookie, referer, num_headers, accept_lang)
}

// JA4H_b部分：计算请求头的SHA256哈希值，按顺序排列
func JA4H_b(req *http.Request) string {
	ordered_headers := make([]string, 0, len(req.Header))
	for h := range req.Header {
		ordered_headers = append(ordered_headers, h)
	}
	sort.Strings(ordered_headers)

	var header_values []string
	for _, h := range ordered_headers {
		header_values = append(header_values, req.Header.Get(h))
	}
	sort.Strings(header_values)

	allheaders := strings.Join(ordered_headers, "") + strings.Join(header_values, "")

	hash := sha256.New()
	hash.Write([]byte(allheaders))
	bs := hash.Sum(nil)
	return fmt.Sprintf("%x", bs)[:12]
}

// JA4H_c部分：计算Cookie字段的哈希值
func JA4H_c(req *http.Request) string {
	if len(req.Cookies()) == 0 {
		return strings.Repeat("0", 12)
	}
	ordered_cookies := make([]string, 0, len(req.Cookies()))
	for _, c := range req.Cookies() {
		ordered_cookies = append(ordered_cookies, c.Name)
	}
	sort.Strings(ordered_cookies)
	allcookies := strings.Join(ordered_cookies, "")

	hash := sha256.New()
	hash.Write([]byte(allcookies))
	bs := hash.Sum(nil)
	return fmt.Sprintf("%x", bs)[:12]
}

// JA4H_d部分：计算Cookie字段及其值的哈希值
func JA4H_d(req *http.Request) string {
	if len(req.Cookies()) == 0 {
		return strings.Repeat("0", 12)
	}
	ordered_cookies := make([]string, 0, len(req.Cookies()))
	for _, c := range req.Cookies() {
		ordered_cookies = append(ordered_cookies, c.Name+"="+c.Value) // 包含Cookie名称和值
	}
	sort.Strings(ordered_cookies)
	allcookies := strings.Join(ordered_cookies, "")

	hash := sha256.New()
	hash.Write([]byte(allcookies))
	bs := hash.Sum(nil)
	return fmt.Sprintf("%x", bs)[:12]
}

// JA4H：基于每个HTTP请求生成HTTP客户端指纹
func JA4H(req *http.Request) string {
	JA4H_a := JA4H_a(req)
	JA4H_b := JA4H_b(req)
	JA4H_c := JA4H_c(req)
	JA4H_d := JA4H_d(req)

	return fmt.Sprintf("%s_%s_%s_%s", JA4H_a, JA4H_b, JA4H_c, JA4H_d)
}
