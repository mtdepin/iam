package datastore

import (
	"fmt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
	config2 "mt-iam/pkg/config"
	logger2 "mt-iam/pkg/logger"
)

const (
	DbUrl  = "db.db_url"
	DbName = "db.db_name"
	DBUser = "db.db_user"
	DBPWD  = "db.db_password"
)

//dbconfig
type DBconfig struct {
	DBName     string `json:"db_name"`
	DbUrl      string `json:"db_url"`
	DbUser     string `json:"db_user"`
	DbPassword string `json:"db_password"`
}

type Database struct {
	DB *gorm.DB
}

var GlobalDB *Database

func InitDB() {
	GlobalDB = &Database{}

	dbUrl := config2.GetString(DbUrl)
	dbname := config2.GetString(DbName)
	dbuser := config2.GetString(DBUser)
	dbpwd := config2.GetString(DBPWD)

	dc := &DBconfig{
		DBName:     dbname,
		DbUrl:      dbUrl,
		DbUser:     dbuser,
		DbPassword: dbpwd,
	}

	// 设置日志
	//newLogger := glog.New(
	//	log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
	//	glog.Config{
	//		SlowThreshold: time.Second, // 慢 SQL 阈值
	//		LogLevel:      glog.Silent,   // Log level
	//		Colorful:      true,        // 彩色打印
	//	},
	//)

	str := fmt.Sprintf("%s:%s@%s/%s?charset=utf8&parseTime=True&loc=Local", dc.DbUser, dc.DbPassword, dc.DbUrl, dc.DBName)
	db, err := gorm.Open(mysql.Open(str), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "t_",
			SingularTable: true,
		},
		//Logger: newLogger,
	})
	if err != nil {
		logger2.FatalIf("Unable to init database", err)
	}

	sqldb, err := db.DB()
	if err != nil {
		logger2.FatalIf("Unable to init database", err)
	}

	sqldb.SetMaxIdleConns(200)
	sqldb.SetMaxOpenConns(500)
	GlobalDB.DB = db
}
