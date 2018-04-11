package inputor

import (
	"encoding/json"
	"fmt"
	"github.com/astaxie/beego/orm"
	"github.com/devplayg/golibs/network"
	"github.com/devplayg/mserver"
	"github.com/devplayg/mserver/objs"
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
	InputJsonDateFormat = "2006-01-02 15:04:05.000"
	DefaultDateFormat   = "2006-01-02 15:04:05"
)

type Inputor struct {
	engine       *mserver.Engine
	detectionDir string
	detectionExt string
	filetransDir string
	filetransExt string
	trafficDir   string
	trafficExt   string
}

func NewInputor(e *mserver.Engine) *Inputor {

	inputor := Inputor{engine: e}
	absPath, _ := filepath.Abs(os.Args[0])
	targetDir := filepath.Dir(absPath)

	// 파일 다운로드 이벤트
	inputor.filetransDir = e.Config["dir.filetrans"]
	if len(inputor.filetransDir) < 1 {
		inputor.filetransDir = targetDir
	}
	inputor.filetransExt = e.Config["ext.filetrans"]
	//log.Debugf("### %s", inputor.filetransExt)
	//log.Debugf("### %s", inputor.filetransExt)
	if len(inputor.filetransExt) < 1 {
		inputor.filetransExt = "log"
	}

	// 파일 탐지 이벤트
	inputor.detectionDir = e.Config["dir.detection"]
	if len(inputor.detectionDir) < 1 {
		inputor.detectionDir = targetDir
	}
	inputor.detectionExt = e.Config["ext.detection"]
	if len(inputor.detectionExt) < 1 {
		inputor.detectionExt = "dat"
	}

	// 트래픽
	inputor.trafficDir = e.Config["dir.traffic"]
	if len(inputor.trafficDir) < 1 {
		inputor.trafficDir = targetDir
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

func (c *Inputor) StartFiletransInputor() error {

	// 허용된 확장자 설정
	extTable := c.getExtTable(c.filetransExt)

	// 검색할 디렉토리 설정
	dirs := c.getTargetDirs(c.filetransDir)

	log.Debugf("Directories for Filetrans: %v", dirs)
	log.Debugf("Extensions for Filetrans: %v", extTable)

	go func() {
		for {
			list := make(objs.LogFileList, 0)

			for _, dir := range dirs { // 검색대상 디렉토리 순차 검색
				err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
					ext := strings.ToLower(filepath.Ext(path))
					if _, ok := extTable[ext]; ok { // 허용된 확장자
						if !f.IsDir() && f.Size() > 0 { // 파일이면
							// 파일경로를 처리대상 파일로 선정
							list = append(list, objs.NewLogFile(path, f.ModTime()))
						}
					}
					return nil
				})
				if err != nil {
					log.Error(err)
				}
			}

			// 파일 처리
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
	log.Debugf("Found files: %d", len(logFileList))

	// 파일 수정시간을 기준으로 오름차순 정렬
	sort.Sort(objs.LogFileList(logFileList))

	// 임시파일 생성 - 파일 다운로드 로그
	tmpFileTrans, err := ioutil.TempFile(os.TempDir(), "log_filetrans_")
	if err != nil {
		return err
	}
	//defer os.Remove(tmpFileTrans.Name())

	// 임시파일 생성 - 파일 정보
	tmpFileHash, err := ioutil.TempFile(os.TempDir(), "pol_filehash_")
	if err != nil {
		return err
	}
	//defer os.Remove(tmpFileHash.Name())

	// 임시파일 생성 - 파일 정보
	tmpFileName, err := ioutil.TempFile(os.TempDir(), "pol_filename_")
	if err != nil {
		return err
	}
	//defer os.Remove(tmpFileName.Name())

	for _, fi := range logFileList {

		// 파일 읽기
		b, err := ioutil.ReadFile(fi.Path)
		if err != nil {
			log.Error(err)
			continue
		}

		// JSON 파싱
		var e objs.FileEvent
		err = json.Unmarshal(b, &e)
		if err != nil {
			log.Errorf("Parse error: %s (%s)", fi.Path, err)
			os.Rename(fi.Path, fi.Path+".err")
			continue
		}

		// JSON 유효성 체크
		if len(e.Info.AnalysisId) < 1 {
			log.Errorf("Invalid format: %s", fi.Path)
			os.Rename(fi.Path, fi.Path+".invalid")
			continue
		}

		// 파싱
		parsedId := strings.Split(e.Info.AnalysisId, "_")
		gid := strings.Join(parsedId[0:4], "_")
		sensorId, err := strconv.Atoi(parsedId[0])
		if err != nil {
			log.Errorf("Invalid sensor id: %s", fi.Path)
			os.Rename(fi.Path, fi.Path+".invalid")
			continue
		}

		// 공통정보 분리
		r := objs.LogFileTrans{
			Gid:       gid,
			TransType: e.Info.Type, // (1:HTTP, 2:FTP, 3:POP3, 4:SMTP, 5: MAIL(?))
			SensorId:  sensorId,
		}

		// 출발지 정보 설정
		if e.Info.Type == objs.HTTP || e.Info.Type == objs.FTP {
			r.SessionId = e.Network.SessionId
			r.SrcIp = e.Network.SrcIpStr
			e.Network.SrcIp = net.ParseIP(e.Network.SrcIpStr)
			r.SrcIpInt = network.IpToInt32(e.Network.SrcIp)
			r.SrcPort = e.Network.SrcPort
			srcCountry, _ := c.engine.GeoIP2.Country(e.Network.SrcIp)
			r.SrcCountry = srcCountry.Country.IsoCode
			r.IppoolSrcGcode, r.IppoolSrcOcode = c.getIppoolCodes(sensorId, e.Network.SrcIp)

			// 목적지 정보 설정
			r.DstIp = e.Network.DstIpStr
			e.Network.DstIp = net.ParseIP(e.Network.DstIpStr)
			r.DstIpInt = network.IpToInt32(e.Network.DstIp)
			r.DstPort = e.Network.DstPort
			dstCountry, _ := c.engine.GeoIP2.Country(e.Network.DstIp)
			r.DstCountry = dstCountry.Country.IsoCode
			r.IppoolDstGcode, r.IppoolDstOcode = c.getIppoolCodes(sensorId, e.Network.DstIp)

			r.Domain = e.Network.Domain
			r.Url = e.Network.Url
			r.GroupCount = e.Info.FileCount
		} else if e.Info.Type == objs.POP3 || e.Info.Type == objs.SMTP {
			r.SessionId = e.Mail.MailId
			r.MailSender = e.Mail.SenderAddr
			r.MailSenderName = e.Mail.SenderName
			r.MailRcpt = e.Mail.RecipientAddr
			r.MailRcptName = e.Mail.RecipientName
			r.GroupCount = e.Info.UrlCount

			r.Domain = e.Mail.Subject

		} else if e.Info.Type == objs.MTA {
			r.SessionId = e.Mail.MailId
			r.MailSender = e.Mail.SenderAddr
			r.MailSenderName = e.Mail.SenderName
			r.MailRcpt = e.Mail.RecipientAddr
			r.MailRcptName = e.Mail.RecipientName
			r.GroupCount = e.Info.UrlCount
		} else {
			log.Debugf("Skipped: %s, TransType: %d", fi.Path, e.Info.Type)
			continue
		}

		for idx, f := range e.Files {
			log.Debugf("File[%d]: %s / %s", idx+1, f.Name, filepath.Base(fi.Path))
			r.Id = f.FileId
			r.Rdate, _ = time.Parse(InputJsonDateFormat, f.Date)
			r.Md5 = f.Md5
			r.Sha256 = f.Sha256
			r.Size = f.Size
			r.Content = f.Content
			r.Score = f.Score
			r.MalType = f.Category
			r.FileType = f.Type
			r.SensorFlags = f.Flags
			r.Filename = f.Name

			if e.Info.Type == objs.HTTP || e.Info.Type == objs.FTP {
			} else if e.Info.Type == objs.POP3 || e.Info.Type == objs.SMTP {
			} else if e.Info.Type == objs.MTA {
			} else {
				log.Debug("### xxx out")
				continue
			}

			lineFileTrans, lineFileHash, lineFileName := c.getLines(&r)
			tmpFileTrans.WriteString(lineFileTrans)
			tmpFileHash.WriteString(lineFileHash)
			if r.TransType < 3 {
				tmpFileName.WriteString(lineFileName)
			}
		}
	}
	tmpFileTrans.Close()
	tmpFileHash.Close()
	tmpFileName.Close()

	// Bulk insert
	err = c.insertFileTrans(tmpFileTrans.Name())
	if err != nil {
		log.Error(err)
		os.Rename(tmpFileTrans.Name(), tmpFileTrans.Name()+".error")
	}
	err = c.insertFileHash(tmpFileHash.Name())
	if err != nil {
		log.Error(err)
		os.Rename(tmpFileHash.Name(), tmpFileHash.Name()+".error")
	}
	err = c.insertFileName(tmpFileName.Name())
	if err != nil {
		log.Error(err)
		os.Rename(tmpFileName.Name(), tmpFileName.Name()+".error")
	}

	return nil
}

func (c *Inputor) getIppoolCodes(sensorId int, ip net.IP) (int, int) {

	log.Debugf("### IP=%s, sensor_id=%d ", ip.String(), sensorId)
	if _, ok := c.engine.IpPoolMap[sensorId]; !ok {
		return 0, 0
	}
	list, _ := c.engine.IpPoolMap[sensorId].ContainingNetworks(ip)
	log.Debugf("### 1, length=%d", len(list))
	if len(list) < 1 {
		return 0, 0
	}
	log.Debug("### 2")
	if len(list) == 1 {
		return list[0].(objs.IpPool).FolderId, list[0].(objs.IpPool).IppoolId
	}

	log.Debug("### 3")
	log.Debugf("### Len: %d", len(list))
	smallest := list[0]
	for i := 1; i < len(list); i++ {
		if list[i].(objs.IpPool).HostCount < smallest.(objs.IpPool).HostCount {
			smallest = list[i]
		}
	}
	log.Debug("### " + smallest.(objs.IpPool).Name)
	return smallest.(objs.IpPool).FolderId, smallest.(objs.IpPool).IppoolId
}

func (i *Inputor) getLines(r *objs.LogFileTrans) (string, string, string) {
	lineFileTrans := fmt.Sprintf("%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%d\t%d\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%d\t%d\t%d\t%s\t%d\r\n",
		r.Id,
		r.Gid,
		r.Rdate.Format(DefaultDateFormat),
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
		r.SensorFlags,
		r.SessionId,
		r.GroupCount,
	)

	lineFileHash := fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%s\t%d\t%d\t%s\t%s\t%s\n",
		r.Md5,
		r.Sha256,
		r.Score,
		r.MalType,
		r.FileType,
		r.Content,
		r.Size,
		r.SensorFlags,
		r.Filename,
		r.Rdate.Format(DefaultDateFormat),
		r.Rdate.Format(DefaultDateFormat),
	)

	lineFileName := fmt.Sprintf("%s\t%s\n",
		r.Md5,
		r.Filename,
	)

	return lineFileTrans, lineFileHash, lineFileName
}

func (i *Inputor) insertFileTrans(path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s' REPLACE INTO TABLE log_filetrans 
		FIELDS TERMINATED BY '\t' 
		LINES TERMINATED BY '\n' 
		(id,gid,rdate,trans_type,sensor_id,ippool_src_gcode,ippool_src_ocode,ippool_dst_gcode,ippool_dst_ocode,md5,sha256,src_ip,src_port,src_country,dst_ip,dst_port,dst_country,domain,url,file_name,mail_sender,mail_sender_name,mail_recipient,mail_recipient_name,mal_type,file_type,content,file_size,score,sensor_flags,session_id,group_count);
	`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	o := orm.NewOrm()
	rs, err := o.Raw(query).Exec()
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("db=log_filetrans, affected_rows=%d", rowsAffected)
	}
	return err
}

func (i *Inputor) insertFileHash(path string) error {

	var query string
	o := orm.NewOrm()

	// 임시 테이블 초기화
	query = "truncate table pol_filehash_temp"
	_, err := o.Raw(query).Exec()
	if err != nil {
		return err
	}

	// 데이터를 임시테이블에 입력
	query = `
		LOAD DATA LOCAL INFILE '%s' REPLACE INTO TABLE pol_filehash_temp 
		FIELDS TERMINATED BY '\t' 
		LINES TERMINATED BY '\n' 
		(md5, sha256, score, mal_type, file_type, content, size, sensor_flags, file_name, rdate, udate)
	`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	_, err = o.Raw(query).Exec()
	if err != nil {
		return err
	}

	// 중복 업데이트(필요한 필드만)
	query = `
		insert into pol_filehash(md5, sha256, score, mal_type, file_type, content, size, sensor_flags, file_name, rdate, udate)
		select md5, sha256, score, mal_type, file_type, content, size, sensor_flags, file_name, rdate, udate
		from pol_filehash_temp
		on duplicate key update
			sha256 = values(sha256),
			score = values(score),
			mal_type = values(mal_type),
			file_type = values(file_type),
			content = values(content),
			size = values(size),
			sensor_flags = values(sensor_flags),
			udate = values(udate)
	`

	rs, err := o.Raw(query).Exec()
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("db=log_filetrans, affected_rows=%d", rowsAffected)
	}
	return err
}

func (i *Inputor) insertFileName(path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s' REPLACE INTO TABLE pol_filename
		FIELDS TERMINATED BY '\t' 
		LINES TERMINATED BY '\n' 
		(md5, name)
	`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	o := orm.NewOrm()
	rs, err := o.Raw(query).Exec()
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("db=pol_filename, affected_rows=%d", rowsAffected)
	}
	return err
}
