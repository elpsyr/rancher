package requests

import (
	"context"
	"fmt"
	"github.com/rancher/wrangler/pkg/randomtoken"
	"k8s.io/apimachinery/pkg/labels"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/rancher/pkg/auth/providerrefresh"
	"github.com/rancher/rancher/pkg/auth/providers"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/rancher/pkg/auth/tokens"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/steve/pkg/auth"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/tools/cache"
)

var (
	ErrMustAuthenticate = httperror.NewAPIError(httperror.Unauthorized, "must authenticate")
)

type Authenticator interface {
	Authenticate(req *http.Request) (*AuthenticatorResponse, error)
	TokenFromRequest(req *http.Request) (*v3.Token, error)
}

type AuthenticatorResponse struct {
	IsAuthed      bool
	User          string
	UserPrincipal string
	Groups        []string
	Extras        map[string][]string
}

func ToAuthMiddleware(a Authenticator) auth.Middleware {
	f := func(req *http.Request) (user.Info, bool, error) {
		authResp, err := a.Authenticate(req)
		if err != nil {
			return nil, false, err
		}
		return &user.DefaultInfo{
			Name:   authResp.User,
			UID:    authResp.User,
			Groups: authResp.Groups,
			Extra:  authResp.Extras,
		}, authResp.IsAuthed, err
	}
	return auth.ToMiddleware(auth.AuthenticatorFunc(f))
}

type ClusterRouter func(req *http.Request) string

func NewAuthenticator(ctx context.Context, clusterRouter ClusterRouter, mgmtCtx *config.ScaledContext) Authenticator {
	tokenInformer := mgmtCtx.Management.Tokens("").Controller().Informer()
	tokenInformer.AddIndexers(map[string]cache.IndexFunc{tokenKeyIndex: tokenKeyIndexer})

	return &tokenAuthenticator{
		ctx:                 ctx,
		tokenIndexer:        tokenInformer.GetIndexer(),
		tokenClient:         mgmtCtx.Management.Tokens(""),
		userAttributeLister: mgmtCtx.Management.UserAttributes("").Controller().Lister(),
		userAttributes:      mgmtCtx.Management.UserAttributes(""),
		userLister:          mgmtCtx.Management.Users("").Controller().Lister(),
		clusterRouter:       clusterRouter,
		userAuthRefresher:   providerrefresh.NewUserAuthRefresher(ctx, mgmtCtx),
		mgr:                 tokens.NewManager(ctx, mgmtCtx),
	}
}

type tokenAuthenticator struct {
	ctx                 context.Context
	tokenIndexer        cache.Indexer
	tokenClient         v3.TokenInterface
	userAttributes      v3.UserAttributeInterface
	userAttributeLister v3.UserAttributeLister
	userLister          v3.UserLister
	clusterRouter       ClusterRouter
	userAuthRefresher   providerrefresh.UserAuthRefresher

	// cfel auto login
	mgr *tokens.Manager
}

const (
	tokenKeyIndex = "authn.management.cattle.io/token-key-index"
)

func tokenKeyIndexer(obj interface{}) ([]string, error) {
	token, ok := obj.(*v3.Token)
	if !ok {
		return []string{}, nil
	}

	return []string{token.Token}, nil
}

func (a *tokenAuthenticator) Authenticate(req *http.Request) (*AuthenticatorResponse, error) {
	authResp := &AuthenticatorResponse{
		Extras: make(map[string][]string),
	}
	token, err := a.TokenFromRequest(req)
	if err != nil {
		return nil, err
	}

	if token.Enabled != nil && !*token.Enabled {
		return nil, errors.Wrapf(ErrMustAuthenticate, "user's token is not enabled")
	}
	if token.ClusterName != "" && token.ClusterName != a.clusterRouter(req) {
		return nil, errors.Wrapf(ErrMustAuthenticate, "clusterID does not match")
	}

	attribs, err := a.userAttributeLister.Get("", token.UserID)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}

	u, err := a.userLister.Get("", token.UserID)
	if err != nil {
		return nil, err
	}

	if u.Enabled != nil && !*u.Enabled {
		return nil, errors.Wrap(ErrMustAuthenticate, "user is not enabled")
	}

	var groups []string
	hitProvider := false
	if attribs != nil {
		for provider, gps := range attribs.GroupPrincipals {
			if provider == token.AuthProvider {
				hitProvider = true
			}
			for _, principal := range gps.Items {
				name := strings.TrimPrefix(principal.Name, "local://")
				groups = append(groups, name)
			}
		}
	}

	// fallback to legacy token.GroupPrincipals
	if !hitProvider {
		for _, principal := range token.GroupPrincipals {
			// TODO This is a short cut for now. Will actually need to lookup groups in future
			name := strings.TrimPrefix(principal.Name, "local://")
			groups = append(groups, name)
		}
	}
	groups = append(groups, user.AllAuthenticated, "system:cattle:authenticated")
	if !strings.HasPrefix(token.UserID, "system:") {
		go a.userAuthRefresher.TriggerUserRefresh(token.UserID, false)
	}

	authResp.IsAuthed = true
	authResp.User = token.UserID
	authResp.UserPrincipal = token.UserPrincipal.Name
	authResp.Groups = groups
	authResp.Extras = getUserExtraInfo(token, u, attribs)
	logrus.Debugf("Extras returned %v", authResp.Extras)

	return authResp, nil
}

func getUserExtraInfo(token *v3.Token, u *v3.User, attribs *v3.UserAttribute) map[string][]string {
	extraInfo := make(map[string][]string)

	if attribs != nil && attribs.ExtraByProvider != nil && len(attribs.ExtraByProvider) != 0 {
		if token.AuthProvider == "local" || token.AuthProvider == "" {
			//gather all extraInfo for all external auth providers present in the userAttributes
			for _, extra := range attribs.ExtraByProvider {
				for key, value := range extra {
					extraInfo[key] = append(extraInfo[key], value...)
				}
			}
			return extraInfo
		}
		//authProvider is set in token
		if extraInfo, ok := attribs.ExtraByProvider[token.AuthProvider]; ok {
			return extraInfo
		}
	}

	extraInfo = providers.GetUserExtraAttributes(token.AuthProvider, token.UserPrincipal)
	//if principalid is not set in extra, read from user
	if extraInfo != nil {
		if len(extraInfo[common.UserAttributePrincipalID]) == 0 {
			extraInfo[common.UserAttributePrincipalID] = u.PrincipalIDs
		}
		if len(extraInfo[common.UserAttributeUserName]) == 0 {
			extraInfo[common.UserAttributeUserName] = []string{u.DisplayName}
		}
	}

	return extraInfo
}

func (a *tokenAuthenticator) TokenFromRequest(req *http.Request) (*v3.Token, error) {

	CFELTokenAuthValue := tokens.GetCookieValueFromRequest(tokens.CfelCookie, req)
	tokenAuthValue := tokens.GetTokenAuthFromRequest(req)
	if CFELTokenAuthValue != "" && tokenAuthValue == "" {

		// sso
		//info, err := GetAuthInfo(CFELTokenAuthValue)
		//if err != nil {
		//	logrus.Errorf("Get SSO AuthInfo err: %v", err)
		//	return nil, err
		//}
		//userToken, err := a.createUserToken(fmt.Sprintf("%s/%s", info.TenantInfo.BizShortCode, info.UserInfo.Account), info.TenantInfo.Name, info.UserInfo.Name)
		//if err != nil {
		//	logrus.Errorf("createUserToken err: %v", err)
		//	return nil, err
		//}
		//tokenAuthValue := fmt.Sprintf("%s:%s", userToken.Name, userToken.Token)
		//addCookieToRequest(tokens.InnerCookie, tokenAuthValue, req)

		return a.createCFELToken(CFELTokenAuthValue, req)

	}

	if tokenAuthValue == "" {
		return nil, ErrMustAuthenticate
	}

	tokenName, tokenKey := tokens.SplitTokenParts(tokenAuthValue)
	if tokenName == "" || tokenKey == "" {
		return nil, ErrMustAuthenticate
	}

	lookupUsingClient := false
	objs, err := a.tokenIndexer.ByIndex(tokenKeyIndex, tokenKey)
	if err != nil {
		if apierrors.IsNotFound(err) {
			lookupUsingClient = true
		} else {
			return nil, errors.Wrapf(ErrMustAuthenticate, "failed to retrieve auth token from cache, error: %v", err)
		}
	} else if len(objs) == 0 {
		lookupUsingClient = true
	}

	var storedToken *v3.Token
	if lookupUsingClient {
		storedToken, err = a.tokenClient.Get(tokenName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				// cfel:
				// 如果有 R_SESS ,但是过期了
				// token 过期去创建新的 token
				if CFELTokenAuthValue != "" {
					return a.createCFELToken(CFELTokenAuthValue, req)
				}
				return nil, ErrMustAuthenticate
			}
			return nil, errors.Wrapf(ErrMustAuthenticate, "failed to retrieve auth token, error: %#v", err)
		}
	} else {
		storedToken = objs[0].(*v3.Token)
	}

	if _, err := tokens.VerifyToken(storedToken, tokenName, tokenKey); err != nil {
		return nil, errors.Wrapf(ErrMustAuthenticate, "failed to verify token: %v", err)
	}

	return storedToken, nil
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
	//loginName := fmt.Sprintf("%s/%s", info.TenantInfo.BizShortCode, info.UserInfo.Account)
	//token, err := a.clusterHasTokenWithLoginName(loginName)
	//if err == nil && token != nil {
	//	return token, nil
	//}

	userToken, err := a.createUserToken(fmt.Sprintf("%s/%s", info.TenantInfo.BizShortCode, info.UserInfo.Account), info.TenantInfo.Name, info.UserInfo.Name)
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
	tokenList, err := a.tokenClient.List(metav1.ListOptions{})
	if err != nil {
		return nil, err // 处理错误
	}

	// 遍历列表，查找是否有匹配 LoginName 的资源
	for _, token := range tokenList.Items {
		if token.UserPrincipal.LoginName == loginName {
			return &token, nil // 找到资源，返回 true
		}
	}
	return nil, errors.New("token not found") // 未找到资源，返回 false
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
		TTLMillis:    0,
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
	k8sToken.ObjectMeta.GenerateName = "token-"

	return k8sToken, nil
}
