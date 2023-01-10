package bdyp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

type FileUploadReq struct {
	Name  string
	File  io.Reader
	RType *int64 `json:"rtype"`
}

type FileUploadSessionStartReq struct {
	Method      string `query:"method"`
	AccessToken string `query:"access_token"`
	Path        string `json:"path"`
	File        io.Reader
	RType       *int64 `json:"rtype"`
}

const blockMaxSize = 4 * 1024 * 1024

func splitBytes(content []byte, size int) [][]byte {
	res := make([][]byte, 0)
	for len(content) > 0 {
		if len(content) > size {
			res = append(res, content[:size])
			content = content[size:]
		} else {
			res = append(res, content)
			content = nil
		}
	}
	return res
}

func (r *Bcloud) Upload(req *FileUploadReq) error {
	bs, err := ioutil.ReadAll(req.File)
	if err != nil {
		return err
	}
	res, err := r.FileUploadSessionStart(&FileUploadSessionStartReq{
		Path:  req.Name,
		File:  bytes.NewReader(bs),
		RType: req.RType,
	})
	if err != nil {
		return err
	} else if res.ReturnType == 2 {
		return nil
	}

	for i, v := range splitBytes(bs, blockMaxSize) {
		err := r.FileUploadSessionAppend(&FileUploadSessionAppendReq{
			Path:     req.Name,
			UploadID: res.UploadID,
			PartSeq:  int64(i),
			File:     bytes.NewReader(v),
		})
		if err != nil {
			return err
		}
	}

	err = r.FileUploadSessionFinish(&FileUploadSessionFinishReq{
		Path:     req.Name,
		File:     bytes.NewReader(bs),
		UploadID: res.UploadID,
		RType:    req.RType,
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *Bcloud) FileUploadSessionStart(req *FileUploadSessionStartReq) (*FileUploadSessionStartResp, error) {
	token, err := r.getAuthToken()
	if err != nil {
		return nil, err
	}

	req.Method = "precreate"
	req.AccessToken = token

	req_, err := req.to()
	if err != nil {
		return nil, err
	}

	resp := new(FileUploadSessionStartResp)

	err = r.requestURLEncode(http.MethodPost, "https://pan.baidu.com/rest/2.0/xpan/file", req_, resp)
	if err != nil {
		return nil, err
	} else if err := resp.Err(); err != nil {
		return nil, err
	}

	if len(resp.BlockList) == 0 {
		resp.BlockList = []int64{0}
	}

	return resp, nil
}

type filePrepareUploadReq struct {
	Method      string  `query:"method"` // 本接口固定为precreate
	AccessToken string  `query:"access_token"`
	Path        string  `json:"path"`        // 上传后使用的文件绝对路径，需要urlencode
	Size        int64   `json:"size"`        // 文件和目录两种情况：上传文件时，表示文件的大小，单位B；上传目录时，表示目录的大小，目录的话大小默认为0
	IsDir       int64   `json:"isdir"`       // 是否为目录，0 文件，1 目录
	BlockList   string  `json:"block_list"`  // 是	["98d02a0f54781a93e354b1fc85caf488", "ca5273571daefb8ea01a42bfa5d02220"]	RequestBody参数	文件各分片MD5数组的json串。block_list的含义如下，如果上传的文件小于4MB，其md5值（32位小写）即为block_list字符串数组的唯一元素；如果上传的文件大于4MB，需要将上传的文件按照4MB大小在本地切分成分片，不足4MB的分片自动成为最后一个分片，所有分片的md5值（32位小写）组成的字符串数组即为block_list。
	AutoInit    int64   `json:"autoinit"`    //	是	1	RequestBody参数	固定值1
	RType       *int64  `json:"rtype"`       // 文件命名策略，默认为0。0 表示不进行重命名，若云端存在同名文件返回错误; 1 表示当path冲突时，进行重命名; 2 表示当path冲突且block_list不同时，进行重命名; 3 当云端存在同名文件时，对该文件进行覆盖
	UploadID    *string `json:"uploadid"`    // 否	P1-MTAuMjI4LjQzLjMxOjE1OTU4NTg==	RequestBody参数	上传ID
	ContentMD5  *string `json:"content-md5"` // 否	b20f8ac80063505f264e5f6fc187e69a	RequestBody参数	文件MD5，32位小写
	SliceMD5    *string `json:"slice-md5"`   // 否	9aa0aa691s5c0257c5ab04dd7eddaa47	RequestBody参数	文件校验段的MD5，32位小写，校验段对应文件前256KB
	LocalCTime  *string `json:"local_ctime"` //	否	1595919297	RequestBody参数	客户端创建时间， 默认为当前时间戳
	LocalMTime  *string `json:"local_mtime"` // 否	1595919297	RequestBody参数	客户端修改时间，默认为当前时间戳
}

type FileUploadSessionStartResp struct {
	errnoErr
	Path       string  `json:"path"`
	UploadID   string  `json:"uploadid"`
	ReturnType int64   `json:"return_type"` // 1 文件在云端不存在，2 文件在云端已存在
	BlockList  []int64 `json:"block_list"`  // 需要上传的分片序号列表，索引从0开始
}

func (r *FileUploadSessionStartResp) Exist() bool {
	return r != nil && r.ReturnType == 2
}

func (r FileUploadSessionStartReq) to() (*filePrepareUploadReq, error) {
	bs, err := io.ReadAll(r.File)
	if err != nil {
		return nil, err
	}
	block := []string{}
	for _, v := range splitBytes(bs, blockMaxSize) {
		block = append(block, getMd5(v))
	}
	blockList, _ := json.Marshal(block)
	_ = blockList
	return &filePrepareUploadReq{
		Method:      r.Method,
		AccessToken: r.AccessToken,
		Path:        r.Path,
		Size:        int64(len(bs)),
		IsDir:       0,
		BlockList:   string(blockList),
		AutoInit:    1,
		RType:       r.RType,
		UploadID:    nil,
		// ContentMD5:  ptr.String(getMd5(bs)),
		// SliceMD5:    nil,
		// LocalCTime:  nil,
		// LocalMTime:  nil,
	}, nil
}

func (r *Bcloud) FileUploadSessionAppend(req *FileUploadSessionAppendReq) error {
	token, err := r.getAuthToken()
	if err != nil {
		return err
	}

	req.Method = "upload"
	req.AccessToken = token
	req.Type = "tmpfile"

	resp := new(fileUploadSessionAppendResp)

	err = r.requestForm(http.MethodPost, "https://d.pcs.baidu.com/rest/2.0/pcs/superfile2", req, resp)
	if err != nil {
		return err
	} else if err := resp.Err(); err != nil {
		return err
	} else if resp.ErrorMsg != "" {
		return fmt.Errorf(resp.ErrorMsg)
	}

	return nil
}

type FileUploadSessionAppendReq struct {
	Method      string    `query:"method"` // 本接口固定为precreate
	AccessToken string    `query:"access_token"`
	Type        string    `query:"type"`     // 固定值 tmpfile
	Path        string    `query:"path"`     // 需要与上一个阶段预上传precreate接口中的path保持一致
	UploadID    string    `query:"uploadid"` // 上一个阶段预上传precreate接口下发的uploadid
	PartSeq     int64     `query:"partseq"`  // 文件分片的位置序号，从0开始，参考上一个阶段预上传precreate接口返回的block_list
	File        io.Reader `file:"file"`      // 是		RequestBody参数	上传的文件内容
}

type fileUploadSessionAppendResp struct {
	errnoErr
	ErrorMsg string `json:"error_msg"`
}

func (r *Bcloud) FileUploadSessionFinish(req *FileUploadSessionFinishReq) error {
	token, err := r.getAuthToken()
	if err != nil {
		return err
	}

	req.Method = "create"
	req.AccessToken = token

	req_, err := req.to()
	if err != nil {
		return err
	}

	resp := new(fileUploadSessionFinishResp)

	err = r.requestURLEncode(http.MethodPost, "https://pan.baidu.com/rest/2.0/xpan/file", req_, resp)
	if err != nil {
		return err
	} else if err := resp.Err(); err != nil {
		return err
	}

	return nil
}

type FileUploadSessionFinishReq struct {
	Method      string    `query:"method"`
	AccessToken string    `query:"access_token"`
	Path        string    `json:"path"`
	File        io.Reader `json:"-"`
	UploadID    string    `json:"uploadid"`
	RType       *int64    `json:"rtype"`
}

type fileUploadSessionFinishReq struct {
	Method      string `query:"method"` // 本接口固定为precreate
	AccessToken string `query:"access_token"`

	Path      string `json:"path"`       // 上传后使用的文件绝对路径，需要urlencode，需要与预上传precreate接口中的path保持一致
	Size      int64  `json:"size"`       // 文件或目录的大小，必须要和文件真实大小保持一致，需要与预上传precreate接口中的size保持一致
	IsDir     int64  `json:"isdir"`      // 0 文件、1 目录，需要与预上传precreate接口中的isdir保持一致
	BlockList string `json:"block_list"` //	是	["7d57c40c9fdb4e4a32d533bee1a4e409"]	RequestBody参数	文件各分片md5数组的json串 需要与预上传precreate接口中的block_list保持一致，同时对应分片上传superfile2接口返回的md5，且要按照序号顺序排列，组成md5数组的json串。
	UploadID  string `json:"uploadid"`   // 预上传precreate接口下发的uploadid
	RType     *int64 `json:"rtype"`
}

func (r *FileUploadSessionFinishReq) to() (*fileUploadSessionFinishReq, error) {
	bs, err := io.ReadAll(r.File)
	if err != nil {
		return nil, err
	}
	block := []string{}
	for _, v := range splitBytes(bs, blockMaxSize) {
		block = append(block, getMd5(v))
	}
	x, _ := json.Marshal(block)
	return &fileUploadSessionFinishReq{
		Method:      r.Method,
		AccessToken: r.AccessToken,
		Path:        r.Path,
		Size:        int64(len(bs)),
		IsDir:       0,
		BlockList:   string(x),
		RType:       r.RType,
		UploadID:    r.UploadID,
	}, nil
}

type fileUploadSessionFinishResp struct {
	errnoErr
}

type Logger interface {
	Info(format string, args ...interface{})
	Error(format string, args ...interface{})
}

func (r *Bcloud) SetLogger(logger Logger) {
	r.logger = logger
}

func (r *Bcloud) info(format string, args ...interface{}) {
	if r.logger != nil {
		r.logger.Info(format, args...)
	}
}

func (r *Bcloud) error(format string, args ...interface{}) {
	if r.logger != nil {
		r.logger.Error(format, args...)
	}
}

type defaultLogger struct{}

func NewDefaultLogger() Logger {
	return &defaultLogger{}
}

func (r *defaultLogger) Info(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

func (r *defaultLogger) Error(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

type errnoErr struct {
	Errno  int64  `json:"errno"`
	Errmsg string `json:"errmsg"`
}

var errnoMsg = map[int64]string{
	0:     "成功",
	2:     "参数错误",
	-10:   "云端容量已满",
	-9:    "文件或目录不存在",
	-8:    "文件或目录已存在",
	-7:    "文件或目录名错误或无权访问",
	-6:    "身份验证失败",
	6:     "不允许接入用户数据",
	10:    "创建文件失败",
	111:   "token 失效 或者 有其他异步任务正在执行",
	31034: "命中接口频控",
	31190: "文件不存在",
	42211: "图片详细信息查询失败",
	42212: "共享目录文件上传者信息查询失败，可重试",
	42213: "共享目录鉴权失败",
	42214: "文件基础信息查询失败",
}

func (e errnoErr) Err() error {
	if e.Errno == 0 {
		return nil
	}
	msg := e.Errmsg
	if msg == "" {
		msg = errnoMsg[e.Errno]
	}
	if msg == "" {
		msg = "未知错误"
	}
	return fmt.Errorf("%d: %s", e.Errno, msg)
}
