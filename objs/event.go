package objs

import (
	"net"
	"time"
)

const (
	HTTP = 1
	FTP = 2
	POP3 = 3
	SMTP = 4
	MTA = 5
)

// Log file
type FileEvent struct {
	Info    feInfo    `json:"info"`
	Network feNetwork `json:"network"`
	Mail    feMail    `json:"mail"`
	Files   []feFile  `json:"file"`
}
type feInfo struct {
	AnalysisId string `json:"analysis_id"`
	Type       int    `json:"type"`
	FileCount  int    `json:"file_cnt"`
	UrlCount   int    `json:"url_cnt"`
}
type feNetwork struct {
	SessionId string `json:"session_id"`
	SrcIp     net.IP `json:"-"`
	SrcIpStr  string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DstIp     net.IP `json:"-"`
	DstIpStr  string `json:"dst_ip"`
	DstPort   int    `json:"dst_port"`
	Protocol  int    `json:"protocol"`
	Domain    string `json:"d_site"`
	Url       string `json:"d_path"`
}
type feMail struct {
	MailId        string `json:"mail_id"`
	SenderName    string `json:"sender_name"`
	SenderAddr    string `json:"sender_addr"`
	RecipientName string `json:"recipient_name"`
	RecipientAddr string `json:"recipient_addr"`
	Subject       string `json:"subject"`
}
type feFile struct {
	FileId   string `json:"f_id"`
	Md5      string `json:"md5"`
	Sha256   string `json:"sha256"`
	Name     string `json:"name"`
	TypeDesc string `json:"extern"`
	Type     int    `json:"extern_code"`
	Category int    `json:"category"`
	Content  string `json:"content"`
	Size     int64  `json:"size"`
	Score    int    `json:"score"`
	Date     string `json:"rdate"`
	Flags    int    `json:"rule_flag"`
}
type LogFile struct {
	Path  string
	Mtime time.Time
}

func NewLogFile(path string, mtime time.Time) *LogFile {
	return &LogFile{path, mtime}
}

type LogFileList []*LogFile

func (a LogFileList) Len() int           { return len(a) }
func (a LogFileList) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a LogFileList) Less(i, j int) bool { return a[i].Mtime.Before(a[j].Mtime) }

// Database
type LogFileTrans struct {
	Id             string
	Gid            string
	Rdate          time.Time
	TransType      int
	SessionId      string
	SensorId       int
	IppoolSrcGcode int
	IppoolSrcOcode int
	IppoolDstGcode int
	IppoolDstOcode int
	Md5            string
	Sha256         string
	SrcIp          string
	SrcIpInt       uint32
	SrcPort        int
	SrcCountry     string
	DstIp          string
	DstIpInt       uint32
	DstPort        int
	DstCountry     string
	Domain         string
	Url            string
	Filename       string
	MailSender     string
	MailSenderName string
	MailRcpt       string
	MailRcptName   string
	MalType        int
	FileType       int
	Score          int
	Size           int64
	Content        string
	Flags          int
	GroupCount     int
	Gdate          time.Time
}

type FileResult struct {
	Md5      string
	Sha256   string
	MalType  int
	FileType int
	Score    int
	Size     int64
	Flags    int
	Rdate    time.Time
	Udate    time.Time
}

/*
{
	"info": {
		"analysis_id": "10_5_1517885082_100000_0",
		"type": 1,
		"file_cnt": 7,
		"url_cnt": 1
	},
	"network": {
		"session_id": "6470973809528342663",
		"src_ip": "180.211.87.73",
		"src_port": "58256",
		"dst_ip": "10.0.7.72",
		"dst_port": "80",
		"protocol": "1",
		"domain": "naver.com",
		"url": "/game.exe"
	},
	"mail": {
		"mail_id": "20180124191402.D05681CE1672@wins.com",
		"sender_name": "김범준",
		"sender_addr": "bumjoon@wins.com",
		"recipient_name": "받는이영어Bumjoon Kim",
		"recipient_addr": "bumjoon@wins21.co.kr",
		"subject": "[WSEC_Ent_Security(한글)]  国語は難しい جزيره العرب."
	},
	"file": [
		{
			"f_id": "10_1_1517885082_100000_1",
			"md5": "adc4e1688cd06ea9069b75ca4da120a3",
			"sha_256": "65846ea3213028dcc988b34e88839ddd14225658fe69aa4958226cacdac0c638",
			"name": "압축테스트 (5).zip",
			"extern": "ZIP",
			"extern_code": 12,
			"content": "application/zip",
			"size": 18292553,
            "score" 100,
			"rdate ": "2018-12-12 01:34:56.000"
		},
		{
			"f_id": "10_1_1517885082_100000_1",
			"md5": "adc4e1688cd06ea9069b75ca4da120a3",
			"sha_256": "65846ea3213028dcc988b34e88839ddd14225658fe69aa4958226cacdac0c638",
			"name": "압축테스트 (5).zip",
			"extern": "ZIP",
			"extern_code": 12,
			"content": "application/zip",
			"size": 18292553,
            "score" 100,
			"rdate ": "2018-12-12 01:34:56.000"
		}
	]
}
*/
