package test

import (
	"encoding/json"
	"fmt"
	"github.com/minio/pkg/bucket/policy"
	iampolicy "github.com/minio/pkg/iam/policy"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

const url = "http://192.168.1.89:10001/minio/admin/v3/"

func TestIsAllowed(t *testing.T) {
	args := &iampolicy.Args{
		AccountName:     "PQuxrmsokUkZgj4GsTss2xnBekG0rPvuVU6+9TGxFo+XtFMew1vCFDz7ScXEUxYg",
		Groups:          []string{"group"},
		Action:          policy.PutObjectAction,
		BucketName:      "",
		ConditionValues: nil,
		IsOwner:         false,
		ObjectName:      "",
	}
	marshal, err := json.Marshal(args)
	if err != nil {
		fmt.Println(err)
	}
	resp, err := http.Post(url+"is-allowed", "application/x-www-form-urlencoded", strings.NewReader(string(marshal)))
	if err != nil {
		fmt.Println(err)
	}
	b, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(b))
}
