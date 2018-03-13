package tsvinputor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/astaxie/beego/orm"
	"github.com/devplayg/mserver"
	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
)

type Inputor struct {
	dir    string
	engine *mserver.Engine
}

func NewInputor(engine *mserver.Engine) *Inputor {
	return &Inputor{
		dir:    engine.Config["storage.watchDir"],
		engine: engine,
	}
}

func (i *Inputor) Start() error {
	go func() {
		for {

			// Read sensors
			sensors, err := mserver.GetSensors()
			if err != nil {
				log.Error(err)
				continue
			}
			//
			// Read files in home directory and insert into tables
			for _, s := range sensors {
				targetDir := filepath.Join(i.dir, s.Ip)

				// If directory exists
				if stat, err := os.Stat(targetDir); err == nil && stat.IsDir() {
					log.Debugf("Reading files in directory: %s", targetDir)
					err := i.Insert(targetDir)
					if err != nil {
						log.Error(err)
						continue
					}
				} else {
					log.Debugf("Failed to read directory: %s", targetDir)
				}
			}
			log.Debugf("Reading directory in %s", i.dir)
			i.Insert(filepath.Join(i.dir))

			// Sleep
			log.Debugf("Sleep %3.1fs", (time.Duration(i.engine.Interval) * time.Millisecond).Seconds())

			time.Sleep(time.Duration(i.engine.Interval) * time.Millisecond)
		}
	}()

	return nil
}

func (i *Inputor) Insert(dir string) error {
	o := orm.NewOrm()
	files, err := filepath.Glob(filepath.Join(dir, "*.[123]"))
	if err != nil {
		return err
	}

	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}

		var e error
		if !fi.IsDir() {
			fname := filepath.Join(dir, fi.Name())
			if strings.HasSuffix(fname, ".1") {
				e = i.insertEvent1(o, fname)

			} else if strings.HasSuffix(fname, ".2") {
				e = i.insertEvent2(o, fname)

			} else if strings.HasSuffix(fname, ".3") {
				e = i.insertEvent3(o, fname)
			} else {
				os.Remove(fname)
			}
			if e != nil {
				log.Error(e)
				os.Rename(fname, fname+".err")
			} else {
				os.Remove(fname)
			}
		}
	}

	return err
}

func (i *Inputor) insertEvent1(o orm.Ormer, path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s'
		INTO TABLE log_event_filetrans
		FIELDS TERMINATED BY '\t'
		LINES TERMINATED BY '\r\n' (
			@dummy,
			@dummy,
			rdate,
			gdate,
			sensor_code,
			ippool_src_gcode,
			ippool_src_ocode,
			ippool_dst_gcode,
			ippool_dst_ocode,
			session_id,
			category1,
			category2,
			src_ip,
			src_port,
			dst_ip,
			dst_port,
			domain,
			url,
			trans_type,
			filename,
			filesize,
			md5,
			mail_sender,
			mail_recipient,
			mail_contents_type,
			mail_contents,
			download_result,
			src_country,
			dst_country,
			protocol
		)`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	rs, err := o.Raw(query).Exec()
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("Type: 1, Affected rows: %d", rowsAffected)
	}
	return err
}

func (i *Inputor) insertEvent2(o orm.Ormer, path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s'
		INTO TABLE log_event_common
		FIELDS TERMINATED BY '\t'
		LINES TERMINATED BY '\r\n' (
			@dummy,
			@dummy,
			rdate,
			gdate,
			sensor_code,
			ippool_src_gcode,
			ippool_src_ocode,
			ippool_dst_gcode,
			ippool_dst_ocode,
			session_id,
			category1,
			category2,
			src_ip,
			src_port,
			dst_ip,
			dst_port,
			domain,
			url,
			risk_level,
			result,
			src_country,
			dst_country,
			protocol
		)`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	rs, err := o.Raw(query).Exec()
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("Type: 2, Affected rows: %d", rowsAffected)
	}
	return err
}

func (i *Inputor) insertEvent3(o orm.Ormer, path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s'
		REPLACE INTO TABLE pol_file_md5
		FIELDS TERMINATED BY '\t'
		LINES TERMINATED BY '\r\n' (
			@dummy,
			@dummy,
			@dummy,
			md5,
			score,
			category,
			judge,
			filesize,
			filetype,
			private_type,
			private_string,
			detect_flag,
			local_vaccine,
			malware_name
		)`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	rs, err := o.Raw(query).Exec()
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("Type: 3, Affected rows: %d", rowsAffected)
	}
	return err
}
