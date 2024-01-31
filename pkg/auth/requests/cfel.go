package requests

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rancher/rancher/pkg/auth/tokens"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/randomtoken"
	"github.com/sirupsen/logrus"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
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

// updateCookie 设置 InnerCookie，更新cookie
func (a *tokenAuthenticator) updateCookie(token *v3.Token, req *http.Request) {
	tokenAuthValue := fmt.Sprintf("%s:%s", token.Name, token.Token)
	addCookieToRequest(tokens.InnerCookie, tokenAuthValue, req)
}

// 判断 cfel-token 是否有效
func isValidateCfelToken(token *v3.Token, cfel string) bool {
	// sso
	info, err := GetAuthInfo(cfel)
	if err != nil {
		logrus.Errorf("Get SSO AuthInfo err: %v", err)
		return false
	}
	// format like ：xxx-xxxxx
	//userInfo := fmt.Sprintf("%s-%s", info.TenantInfo.BizShortCode, info.UserInfo.Account)
	userInfo := fmt.Sprintf("%s", info.UserInfo.Account)
	if userInfo == token.Name {
		return true
	}
	return false
}

// createCFELToken 根据 cfel-token 创建 rancher token,并设置 InnerCookie
func (a *tokenAuthenticator) createCFELToken(cfel string, req *http.Request) (*v3.Token, error) {
	// sso
	info, err := GetAuthInfo(cfel)
	if err != nil {
		logrus.Errorf("Get SSO AuthInfo err: %v", err)
		return nil, err
	}
	// 判断资源是否已经创建
	// 这里要看是否是
	//loginName := fmt.Sprintf("%s-%s", info.TenantInfo.BizShortCode, info.UserInfo.Account)
	loginName := fmt.Sprintf("%d", info.UserInfo.ID)
	tokenGet, err := a.clusterHasTokenWithLoginName(loginName)
	if err == nil && tokenGet != nil {
		tokenAuthValue := fmt.Sprintf("%s:%s", tokenGet.Name, tokenGet.Token)
		addCookieToRequest(tokens.InnerCookie, tokenAuthValue, req)
		return tokenGet, nil
	}

	//userToken, err := a.createUserToken(fmt.Sprintf("%s/%s", info.TenantInfo.BizShortCode, info.UserInfo.Account), info.TenantInfo.Name, info.UserInfo.Name)
	userToken, err := a.createUserToken(fmt.Sprintf("%d", info.UserInfo.ID), info.TenantInfo.Name, info.UserInfo.Name)
	if err != nil {
		logrus.Errorf("createUserToken err: %v", err)
		return nil, err
	}
	tokenAuthValue := fmt.Sprintf("%s:%s", userToken.Name, userToken.Token)
	addCookieToRequest(tokens.InnerCookie, tokenAuthValue, req)
	return userToken, nil
}

func (a *tokenAuthenticator) clusterHasTokenWithLoginName(loginName string) (*v3.Token, error) {
	// 使用 List 方法获取所有 Token 资源
	tokenGet, err := a.tokenClient.Get(loginName, metav1.GetOptions{})
	if err != nil {
		return nil, err // 处理错误
	}
	return tokenGet, nil
}

func addCookieToRequest(k, v string, req *http.Request) {
	tokenCookieUse := &http.Cookie{
		Name:     k,
		Value:    v,
		Secure:   true,
		Path:     "/",
		HttpOnly: true,
	}
	req.AddCookie(tokenCookieUse)
}

// createUserToken 根据用户登录名创建 token
func (a *tokenAuthenticator) createUserToken(loginName, tenantName, userName string) (*v3.Token, error) {
	getUser, err := a.getUser(loginName)
	if err != nil {
		logrus.Errorf("failed to get get User")
		return &v3.Token{}, errors.New("failed to get User")
	}
	// create token crd
	k8sToken, err := buildToken(loginName, getUser.Name, getUser.PrincipalIDs[0], fmt.Sprintf("%s/%s", tenantName, userName))
	if err != nil {
		logrus.Errorf("buildToken err: %v", err)
		return &v3.Token{}, errors.New("failed to buildToken")
	}
	create, err := a.tokenClient.Create(k8sToken)
	if err != nil {
		logrus.Errorf("token create err: %v ", err)
		return &v3.Token{}, errors.New("failed to create token")
	}
	return create, nil

}

// getUser 根据 loginName 获取用户对象
func (a *tokenAuthenticator) getUser(loginName string) (*v3.User, error) {
	list, err := a.userLister.List("", labels.Everything())
	if err != nil {
		logrus.Errorf("userLister.List err: %v", err)
		return &v3.User{}, errors.New("failed to generate token key")
	}

	if len(list) == 0 {
		return &v3.User{}, errors.New("no user name:" + loginName)
	}
	for _, user := range list {
		// user.Username 记录的是 loginName
		if user.Username == loginName {
			return user, nil
		}
	}
	return &v3.User{}, errors.New("no user name:" + loginName)
}

func buildToken(loginName, userId, principalIDs, displayName string) (*v3.Token, error) {
	key, err := randomtoken.Generate()
	if err != nil {
		logrus.Errorf("Failed to generate token key: %v", err)
		return nil, errors.New("failed to generate token key")
	}

	k8sToken := &v3.Token{
		UserPrincipal: v3.Principal{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: principalIDs,
			},
			DisplayName:    displayName,
			LoginName:      loginName,
			ProfilePicture: "",
			ProfileURL:     "",
			PrincipalType:  "user",
			Me:             true,
			MemberOf:       true,
			Provider:       "local",
			ExtraInfo:      nil,
		},
		IsDerived:    false,
		TTLMillis:    3600000,
		UserID:       userId,
		AuthProvider: "local",
		Description:  "",
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{},
		},
	}
	if k8sToken.ObjectMeta.Labels == nil {
		k8sToken.ObjectMeta.Labels = make(map[string]string)
	}
	k8sToken.APIVersion = "management.cattle.io/v3"
	k8sToken.Kind = "Token"
	k8sToken.Token = key
	k8sToken.ObjectMeta.Labels[tokens.UserIDLabel] = k8sToken.UserID
	k8sToken.ObjectMeta.GenerateName = "cfel-auth"
	//k8sToken.ObjectMeta.Name = fmt.Sprintf("%s-%s", strings.Split(loginName, "/")[0], strings.Split(loginName, "/")[1])
	k8sToken.ObjectMeta.Name = fmt.Sprintf("%s", loginName)

	return k8sToken, nil
}
