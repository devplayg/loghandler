package inputor

import (
	"encoding/json"
	"fmt"
	"github.com/astaxie/beego/orm"
	"github.com/devplayg/golibs/network"
	"github.com/devplayg/mserver"
	"github.com/devplayg/mserver/objs"
	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultInputDateFormat  = "2006-01-02 15:04:05.000"
	DefaultOutputDateFormat = "2006-01-02 15:04:05"
)

type Inputor struct {
	engine       *mserver.Engine
	ipDB         *geoip2.Reader
	detectionDir string
	detectionExt string
	filetransDir string
	filetransExt string
	trafficDir   string
	trafficExt   string
}

func NewInputor(e *mserver.Engine, ipDB *geoip2.Reader) *Inputor {

	inputor := Inputor{engine: e, ipDB: ipDB}
	homeDir := "c:/temp/json"

	// 파일 다운로드 이벤트
	inputor.filetransDir = e.Config["dir.filetrans"]
	if len(inputor.filetransDir) < 1 {
		inputor.filetransDir = homeDir
	}
	inputor.filetransExt = e.Config["ext.filetrans"]
	if len(inputor.filetransExt) < 1 {
		inputor.filetransExt = "log"
	}

	// 파일 탐지 이벤트
	inputor.detectionDir = e.Config["dir.detection"]
	if len(inputor.detectionDir) < 1 {
		inputor.detectionDir = homeDir
	}
	inputor.detectionExt = e.Config["ext.detection"]
	if len(inputor.detectionExt) < 1 {
		inputor.detectionExt = "dat"
	}

	// 트래픽
	inputor.trafficDir = e.Config["dir.traffic"]
	if len(inputor.trafficDir) < 1 {
		inputor.trafficDir = homeDir
	}
	inputor.trafficExt = e.Config["ext.traffic"]
	if len(inputor.trafficExt) < 1 {
		inputor.trafficExt = "traffic"
	}

	return &inputor
}

func (c *Inputor) getExtTable(str string) map[string]bool {
	m := make(map[string]bool)
	re := regexp.MustCompile("[\\s|,]+")
	list := re.Split(strings.TrimSpace(str), -1)
	for _, a := range list {
		m["."+strings.ToLower(a)] = true
	}
	return m
}

func (c *Inputor) getTargetDirs(str string) []string {
	re := regexp.MustCompile("[\\s|,]+")
	return re.Split(strings.TrimSpace(str), -1)
}

func (c *Inputor) StartFiletransInputor(errChan chan<- error) error {

	// 허용된 확장자 설정
	extTable := c.getExtTable(c.filetransExt)

	// 검색할 디렉토리 설정
	dirs := c.getTargetDirs(c.filetransDir)

	log.Debugf("Extensions: %v", extTable)
	log.Debugf("Directories: %v", dirs)

	go func() {
		for {
			list := make(objs.LogFileList, 0)

			for _, dir := range dirs { // 검색대상 디렉토리 순차 검색
				err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
					ext := strings.ToLower(filepath.Ext(path))
					if _, ok := extTable[ext]; ok { // 허용된 확장자
						if !f.IsDir() && f.Size() > 0 { // 파일이면
							// 처리대상 파일로 선정
							list = append(list, objs.NewLogFile(path, f.ModTime()))

							// 파일 유효성 체크 추후 추가
						}
					}
					return nil
				})
				if err != nil {
					errChan <- err
				}
			}
			//log.Debugf("List: %+v", list)

			c.processFiletransLog(list)

			// Sleep
			time.Sleep(time.Duration(c.engine.Interval) * time.Millisecond)
		}
	}()

	return nil
}

func (c *Inputor) processFiletransLog(logFileList objs.LogFileList) error {
	if len(logFileList) < 1 {
		return nil
	}

	// 파일 수정시간을 기준으로 오름차순 정렬
	sort.Sort(objs.LogFileList(logFileList))

	// Parse json

	tmpFile, err := ioutil.TempFile("c:/temp", "log_")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name()) // clean up

	for _, fi := range logFileList {
		b, err := ioutil.ReadFile(fi.Path)
		if err != nil {
			log.Error(err)
			continue
		}

		// JSON 읽기
		var e objs.FileEvent
		err = json.Unmarshal(b, &e)
		if err != nil {
			log.Errorf("Parse error: %s (%s)", fi.Path, err)
			os.Rename(fi.Path, fi.Path+".err")
			continue
		}

		if len(e.Info.AnalysisId) < 1 {
			log.Errorf("Invalid format: %s", fi.Path)
			os.Rename(fi.Path, fi.Path+".invalid")
			continue
		}

		// 파싱
		parsedId := strings.Split(e.Info.AnalysisId, "_")
		gid := strings.Join(parsedId[0:4], "_")
		sensorId, _ := strconv.Atoi(parsedId[0])
		for _, f := range e.Files {
			t, _ := time.Parse(DefaultInputDateFormat, f.Date)
			r := objs.LogFileTrans{
				Id:        f.FileId,
				Gid:       gid,
				Rdate:     t,
				TransType: e.Info.Type, // (1:HTTP, 2:FTP, 3:POP3, 4:SMTP, 5: MAIL(?))
				SensorId:  sensorId,
				Md5:       f.Md5,
				Sha256:    f.Sha256,
				Size:      f.Size,
				Content:   f.Content,
			}

			if e.Info.Type >= 1 && e.Info.Type <= 2 { // HTTP, FTP
				r.SessionId = e.Network.SessionId
				r.FileType = f.Type

				// Source information
				r.SrcIp = e.Network.SrcIpStr
				e.Network.SrcIp = net.ParseIP(e.Network.SrcIpStr)
				r.SrcIpInt = network.IpToInt32(e.Network.SrcIp)
				r.SrcPort = e.Network.SrcPort
				srcCountry, _ := c.ipDB.Country(e.Network.SrcIp)
				r.SrcCountry = srcCountry.Country.IsoCode

				// Destination
				r.DstIp = e.Network.DstIpStr
				e.Network.DstIp = net.ParseIP(e.Network.DstIpStr)
				r.DstIpInt = network.IpToInt32(e.Network.DstIp)
				r.DstPort = e.Network.DstPort
				dstCountry, _ := c.ipDB.Country(e.Network.DstIp)
				r.DstCountry = dstCountry.Country.IsoCode
			} else if e.Info.Type >= 3 && e.Info.Type <= 5 { // POP3, SMTP, MAIL
				r.SessionId = e.Mail.MailId
				r.Size = f.Size
				r.MailSender = e.Mail.SenderAddr
				r.MailSenderName = e.Mail.SenderName
				r.MailRcpt = e.Mail.RecipientAddr
				r.MailRcptName = e.Mail.RecipientName
				r.Filename = e.Mail.Subject

			} else {
				continue
			}
			line := fmt.Sprintf("%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%d\t%d\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%d\t%d\t%d\t%s\t%d\r\n",
				r.Id,
				r.Gid,
				r.Rdate.Format(DefaultOutputDateFormat),
				r.TransType,
				r.SensorId,
				r.IppoolSrcGcode,
				r.IppoolSrcOcode,
				r.IppoolDstGcode,
				r.IppoolDstOcode,
				r.Md5,
				r.Sha256,
				r.SrcIpInt,
				r.SrcPort,
				r.SrcCountry,
				r.DstIpInt,
				r.DstPort,
				r.DstCountry,
				r.Domain,
				r.Url,
				r.Filename,
				r.MailSender,
				r.MailSenderName,
				r.MailRcpt,
				r.MailRcptName,
				r.MalType,
				r.FileType,
				r.Content,
				r.Size,
				r.Score,
				r.Flags,
				r.SessionId,
				r.GroupCount,
			)
			tmpFile.WriteString(line)
			log.Debug(line)
		}
	}
	tmpFile.Close()

	// Bulk insert
	c.insert(tmpFile.Name())

	return nil
}

func (i *Inputor) insert(path string) error {
	log.Debug(path)
	query := `
		LOAD DATA LOCAL INFILE '%s' 
		REPLACE INTO TABLE log_filetrans 
		FIELDS TERMINATED BY '\t' 
		LINES TERMINATED BY '\r\n' 
		(id,gid,rdate,trans_type,sensor_id,ippool_src_gcode,ippool_src_ocode,ippool_dst_gcode,ippool_dst_ocode,md5,sha256,src_ip,src_port,src_country,dst_ip,dst_port,dst_country,domain,url,filename,mail_sender,mail_sender_name,mail_recipient,mail_recipient_name,maltype,filetype,content,size,score,flags,session_id,group_count);
	`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	o := orm.NewOrm()
	rs, err := o.Raw(query).Exec()
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("Type: 2, Affected rows: %d", rowsAffected)
	}
	return err
}
