package test

import (
	"encoding/json"
	"fmt"
	"github.com/minio/pkg/bucket/policy"
	iampolicy "github.com/minio/pkg/iam/policy"
	"net/http"
	"strings"
	"testing"
)

const url = "http://localhost:10000/"

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
	http.Post(url+"iam/isAllowed", "", strings.NewReader(string(marshal)))
}
