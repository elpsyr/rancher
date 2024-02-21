package requests

import (
	"fmt"
	"os"
	"testing"
)

func TestGetAuthInfo(t *testing.T) {

	os.Setenv("CFEL_SSO_DOMAIN", "sso.puhui.chengfengerlai.com")
	info, err := GetAuthInfo("1a71f3c0-2c47-4139-aebe-0bb52dd2a4d4")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(info)
}
