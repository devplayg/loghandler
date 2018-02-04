package mserver

import (
	"github.com/astaxie/beego/orm"
)


type DbInfo struct {
	DriverName string
	Host       string
	Port       string
	Username   string
	Password   string
}

type Sensor struct {
	Ip   string
	Port string
}

type MemberAsset struct {
	MemberId int
	AssetId  int
}

func GetSensors() ([]Sensor, error) {
	var sensors []Sensor
	o := orm.NewOrm()
	_, err := o.Raw("select ip, port from ast_sensor").QueryRows(&sensors)
	return sensors, err
}

func GetMemberAssets() (map[int][]int, error) {
	query := "select asset_id, member_id from mbr_asset where asset_type = 2"
	assets := make(map[int][]int)

	o := orm.NewOrm()
	var rows []MemberAsset
	_, err := o.Raw(query).QueryRows(&rows)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if _, ok := assets[r.AssetId]; !ok {
			assets[r.AssetId] = make([]int, 0)
		}
		assets[r.AssetId] = append(assets[r.AssetId], r.MemberId)
	}
	return assets, nil
}

