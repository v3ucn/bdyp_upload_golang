# bdyp_upload_golang

## 安装

```
go get github.com/zcxey2911/bdyp_upload_golang
```

## 获取code

访问obb网址：https://openapi.baidu.com/oauth/2.0/authorize?client_id=你的应用key&response_type=code&redirect_uri=oob&scope=basic+netdisk

## 调用上传

```
package main

import (
	"fmt"
	bdyp "github.com/zcxey2911/bdyp_upload_golang"
	"os"
)

func main() {

	var bcloud = bdyp.Bcloud{}

	// 获取token
	res, err := bcloud.GetToken("obb获取的code", "oob", "应用appkey", "应用appsecret")

	fmt.Println(res)

	if err != nil {
		fmt.Println("err", err)
	} else {
		fmt.Printf("接口的token是: %#v\n", res.AccessToken)
	}
	// 读取文件
	f, err := os.Open("/Users/liuyue/Downloads/ju1.webp")
	if err != nil {
		fmt.Println("err", err)
		return
	}
	defer f.Close()

	// 上传文件
	print(bcloud.Upload(&bdyp.FileUploadReq{
		Name:  "/apps/云盘备份/ju2.webp",
		File:  f,
		RType: nil,
	}))

}

```