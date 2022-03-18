package config

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
	util "github.com/ipfs/go-ipfs-util"
	"github.com/spf13/viper"
)

var disConfig *DisConfig

// DisConfig local yml yaml in local
type DisConfig struct {
	Config *viper.Viper
}

func InitConfig() error {
	fmt.Println("init config")
	configInstance := InitViper("config")
	defer func() {
		configInstance.WatchConfig()
		configInstance.Config.OnConfigChange(func(e fsnotify.Event) {
			fmt.Println("配置发生变更：", e.Name)
		})
	}()
	curPath, _ := os.Getwd()
	confPath := curPath + "/conf/"
	configInstance.AddConfigPath(confPath)
	if !util.FileExists(confPath + "config.yml") {
		fmt.Println(confPath + "config.yml do not exist")
	}
	configInstance.SetConfigName("config")
	if err := configInstance.ReadInConfig(); err != nil {
		fmt.Println("error when reading config file error: ", err)
	}
	return nil
}

// ConfigInstance get instance  of config
func ConfigInstance() *DisConfig {
	return disConfig
}

func InitViper(LocalServiceId string) *DisConfig {
	cViper := viper.New()
	cViper.SetEnvPrefix(LocalServiceId)
	cViper.AutomaticEnv()
	cViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	disConfig = &DisConfig{
		Config: cViper,
	}
	return disConfig
}

// WatchConfig
func (config *DisConfig) WatchConfig() {
	config.Config.WatchConfig()
}

// SetConfigName
func (config *DisConfig) SetConfigName(in string) {
	config.Config.SetConfigName(in)
}

// SetEnvironment set viper in config
func (config *DisConfig) AddConfigPath(confPath string) {
	config.Config.AddConfigPath(confPath)
}

// EvnChanged will merge
func (config *DisConfig) EvnChanged(in io.Reader) {
	config.Config.MergeConfig(in)
}

// EvnChanged will merge
func (config *DisConfig) ReadInConfig() error {
	return config.Config.ReadInConfig()
}

// ReadLocationConfig get config content
func (config *DisConfig) ReadLocationConfig(defaultPath string) (error, string) {
	nacosFile, err := ioutil.ReadFile(defaultPath)
	if err != nil {
		return err, ""
	}
	readContent := string(nacosFile)
	for _, value := range os.Environ() {
		keyValue := strings.Split(value, "=")
		if len(keyValue) == 2 {
			find := fmt.Sprintf("${%s}", keyValue[0])
			if strings.Index(readContent, find) > 0 {
				readContent = strings.ReplaceAll(readContent, find, keyValue[1])
			}
		}
	}
	return nil, readContent
}

func GetString(key string) string {
	ins := ConfigInstance()
	return ins.Config.GetString(key)
}

func GetInt(key string) int {
	ins := ConfigInstance()
	return ins.Config.GetInt(key)
}

func GetBool(key string) bool {
	ins := ConfigInstance()
	return ins.Config.GetBool(key)
}
