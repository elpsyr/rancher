package requests

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
)

type Response struct {
	ExtMap    ExtMap      `json:"extMap"`
	Success   bool        `json:"success"`
	ErrorCode interface{} `json:"errorCode"`
	ErrorMsg  *string     `json:"errorMsg"`
	Content   Content     `json:"content"`
}
type ExtMap struct {
}
type TenantInfo struct {
	ID           int64  `json:"id"`
	BizShortCode string `json:"bizShortCode"`
	Name         string `json:"name"`
	ShortName    string `json:"shortName"`
	Logo         string `json:"logo"`
}
type UserInfo struct {
	ID      int64       `json:"id"`
	Name    string      `json:"name"`
	Mobile  string      `json:"mobile"`
	Email   string      `json:"email"`
	Avatar  interface{} `json:"avatar"`
	Account string      `json:"account"`
}
type Content struct {
	TenantInfo TenantInfo `json:"tenantInfo"`
	UserInfo   UserInfo   `json:"userInfo"`
}

func GetAuthInfo(token string) (*Content, error) {
	// 设置请求的URL
	ssoDomain := os.Getenv("CFEL_SSO_DOMAIN")
	if ssoDomain == "" {

		return nil, errors.New("CFEL_SSO_DOMAIN not set")
	}

	url := fmt.Sprintf("https://%s/external/api/v1/auth/verify.json", ssoDomain)

	// 创建HTTP客户端
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 创建GET请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logrus.Error("Error creating request:", err)
		return nil, err
	}

	// 添加Header
	req.Header.Add("Cfel-Token", token)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		logrus.Error("Error sending request:", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 读取返回结果
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Error("Error reading response body:", err)
		return nil, err
	}

	// 反序列化返回结果到结构体
	var result Response
	err = json.Unmarshal(body, &result)
	if err != nil {
		logrus.Error("Error unmarshalling response:", err)
		return nil, err
	}

	if result.Success != true {
		return nil, errors.New(*result.ErrorMsg)
	}

	return &result.Content, nil
}
